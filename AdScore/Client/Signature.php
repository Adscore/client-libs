<?php namespace AdScore\Client;

/**
 * Example library for validation response signatures from AdScore system
 *
 * @author	Bartosz Derleta <bartosz@derleta.com>
 * @copyright 	AdScore Technologies DMCC [AE]
 * @version 	20230905
 */

class SignatureError extends \Exception {}
class SignatureFormatError extends SignatureError {}
class SignatureCryptError extends SignatureError {}
class SignatureVersionError extends SignatureError {}
class SignatureVerifyError extends SignatureError {}

if (!function_exists('hash_equals')) {
    function hash_equals($known_string, $user_string) {
        $kLen = strlen($known_string);
        $uLen = strlen($user_string);
        if ($kLen !== $uLen) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $kLen; $i++) {
            $result |= ord($known_string[$i]) ^ ord($user_string[$i]);
        }
        return $result === 0;
    }
}

class Signature {

    /* CONFIGURATION */
    /* Validity time of full screening performed for visitor */
    public static $requestExpiry = 21660;
    /* You may prefer to store HMAC keys decoded, this switch will skip base64 decoding of supplied HMAC key */
    public static $useRawHmacKey = true;

    /* VERSION-SPECIFIC CONSTANTS */
    /* Supported signature types */
    const HASH_SHA256 = 1;
    const SIGN_SHA256 = 2;

    public static  $results = [
        0 => ['verdict' => 'ok', 'name' => 'Clean'],
        3 => ['verdict' => 'junk', 'name' => 'Junk'],
        6 => ['verdict' => 'proxy', 'name' => 'Proxy'],
        9 => ['verdict' => 'bot', 'name' => 'Bot'],
    ];

    public static $fieldIds = [
        /* ulong fields */
        0x00 => ['name' => 'requestTime', 'type' => 'ulong'],
        0x01 => ['name' => 'signatureTime', 'type' => 'ulong'],

        0x10 => ['name' => 'ipV4', 'type' => 'ulong'],
        /* ushort fields */
        0x40 => ['name' => null, 'type' => 'ushort'], /* Reserved for future use */
        /* uchar fields */
        0x80 => ['name' => 'masterSignType', 'type' => 'uchar'],
        0x81 => ['name' => 'customerSignType', 'type' => 'uchar'],
        /* string fields */
        0xC0 => ['name' => 'masterToken', 'type' => 'string'],
        0xC1 => ['name' => 'customerToken', 'type' => 'string'],
        0xC2 => ['name' => 'masterTokenV6', 'type' => 'string'],
        0xC3 => ['name' => 'customerTokenV6', 'type' => 'string'],
        0xC4 => ['name' => 'ipV6', 'type' => 'string'],
        0xC5 => ['name' => 'masterChecksum', 'type' => 'string'],

        0xD0 => ['name' => 'userAgent', 'type' => 'string']
    ];

    const HEADER_LENGTH = 11;
    const VERSION = 5;
    const ENCRYPTION_METHOD = 'aes-256-cbc';
    const METHOD = 0x0200;
    const SERIALIZATION_S = 'S';
    const SERIALIZATION_H = 'H';

    /**
     * Verify received signature
     *
     * @param 	$signature
     * @param	$key		Salt or key, depending on $signType param of source getResult invoc.
     * @param	$ipAddress
     * @param 	$userAgent
     * @param 	$signRole	Preferrably one of SignRole::X constants
     * @return				Provides verdict and timestamp
     */
    public static function verify($signature, $key, $ipAddresses, $userAgent, $signRole = 'customer') {
        if (!is_array($ipAddresses))
            $ipAddresses = array_filter(array_map(function($a) { return trim($a); }, preg_split('/[^0-9a-f\.\:]+/', $ipAddresses)));
        try {
            $result = self::parseResult5($signature, $key);
            self::checkResult($result, $ipAddresses, $userAgent);
        } catch (SignatureVersionError $error) {
            $result = self::verifyTokens($signature, $key, $ipAddresses, $userAgent, $signRole);
        }
        if (time() - $result['requestTime'] > self::$requestExpiry)
            throw new SignatureError('Signature base expired', 11);
        return $result;
    }

    protected static function verifyEmbeddedIpv6($data, $result, $key, $userAgent, $signRole = 'master') {
        if ($signRole !== 'master')
            return null; /* Unable to verify signature integrity */
        if ((!isset($data['ipV6'])) || (empty($data['ipV6'])))
            return null; /* No IPv6 supplied */
        if ((!isset($data[$signRole . 'TokenV6'])) || (empty($data[$signRole . 'TokenV6'])))
            return null; /* No IPv6 tokens supplied */
        $checksum = self::hashData($data[$signRole . 'Token'] . $data[$signRole . 'TokenV6'], $key, 'haval128,4');
        if (strcmp($checksum, $data[$signRole . 'Checksum']) !== 0)
            return null; /* Integrity not preserved */
        /* V4-V6 integrity is preserved, but we still need to validate passed IPv6 against TokenV6 */
        $ipAddress = @inet_ntop($data['ipV6']);
        if (empty($ipAddress))
            return null; /* Not valid IPv6 struct */
        $signType = $data[$signRole . 'SignType'];
        $signatureBase = self::getBase($result, $data['requestTime'], $data['signatureTime'], $ipAddress, $userAgent);
        switch ($signType) {
            case self::HASH_SHA256 :
                $xToken = self::hashData($signatureBase, $key, 'sha256');
                if (hash_equals($xToken, $data[$signRole . 'TokenV6']))
                    return $ipAddress;
            /* Customer verification currently unsupported */
        }
        return null;
    }

    /**
     * Verify signature tokens
     */
    protected static function verifyTokens($signature, $key, $ipAddresses, $userAgent, $signRole = 'customer') {
        /* Autodetect signature version */
        try {
            $data = self::parseResult4($signature);
        } catch (SignatureVersionError $e) {
            $data = self::parseResult3($signature);
        }
        if (!isset($data[$signRole . 'Token']))
            throw new SignatureError('Invalid sign role', 2);
        $signType = $data[$signRole . 'SignType'];
        foreach ($ipAddresses as $ipAddress) {
            /* Detect whether it's IPv4 or IPv6, normalize */
            $longIp = @ip2long($ipAddress);
            if ($longIp !== false) {
                $ipAddress = long2ip($longIp);
                $token = $data[$signRole . 'Token'];
            } else {
                if (($pton = @inet_pton($ipAddress)) === false)
                    continue;
                $ipAddress = inet_ntop($pton);
                $token = (isset($data[$signRole . 'TokenV6']) ? $data[$signRole . 'TokenV6'] : null);
                if ($token === null)
                    continue;
            }
            /* Check all possible results */
            foreach (self::$results as $result => $meta) {
                $signatureBase = self::getBase($result, $data['requestTime'], $data['signatureTime'], $ipAddress, $userAgent);
                switch ($signType) {
                    case self::HASH_SHA256 :
                        $xToken = self::hashData($signatureBase, self::$useRawHmacKey ? $key : self::fromBase64($key), 'sha256');
                        if (hash_equals($xToken, $token))
                            return ['verdict' => $meta['verdict'], 'result' => $result, 'ipAddress' => $ipAddress, 'requestTime' => $data['requestTime'], 'signatureTime' => $data['signatureTime'], 'embeddedIpV6' => self::verifyEmbeddedIpv6($data, $result, $key, $userAgent, $signRole)];
                        break;
                    case self::SIGN_SHA256 :
                        $xValid = self::verifyData($signatureBase, $token, $key, 'sha256');
                        if ($xValid)
                            return ['verdict' => $meta['verdict'], 'result' => $result, 'ipAddress' => $ipAddress, 'requestTime' => $data['requestTime'], 'signatureTime' => $data['signatureTime'], 'embeddedIpV6' => self::verifyEmbeddedIpv6($data, $result, $key, $userAgent, $signRole)];
                        break;
                    default :
                        throw new SignatureError('Unrecognized sign type', 3);
                }
            }
        }
        throw new SignatureVerifyError('No verdict matched', 10);
    }

    /**
     * Decode base64 payload
     */
    protected static function fromBase64($string) {
        return base64_decode(strtr($string, ['-' => '+', '_' => '/']));
    }

    /**
     * Verify signature against recreated source data
     */
    protected static function verifyData($data, $signature, $publicKey, $algorithm = 'sha256') {
        while (openssl_error_string() !== false);
        $result = openssl_verify($data, $signature, $publicKey, $algorithm);
        if ($result === -1)
            throw new SignatureCryptError('OpenSSL verify failed: ' . openssl_error_string());
        return ((bool)$result);
    }

    /**
     * Hash signature source data
     */
    protected static function hashData($data, $key, $algorithm = 'sha256') {
        $hash = hash_hmac($algorithm, $data, $key, true);
        if ($hash === false)
            throw new SignatureCryptError('Unsupported hash algorithm: ' . $algorithm);
        return $hash;
    }

    /**
     * Build a signature source data
     */
    protected static function getBase($result, $requestTime, $signatureTime, $ipAddress, $userAgent) {
        return join("\n", func_get_args());
    }

    /**
     * Parse signature version 4
     */
    public static function parseResult4($signature) {
        $signature = self::fromBase64($signature, true);
        if (empty($signature))
            throw new SignatureFormatError('Not a valid base64 signature payload', 4);
        $data = unpack('Cversion/CfieldNum', $signature);
        if ($data['version'] !== 4)
            throw new SignatureVersionError('Signature version not supported', 5);
        $signature = substr($signature, 2);
        for ($i = 0; $i < $data['fieldNum']; ++$i) {
            $field = @unpack('CfieldId', $signature);
            $fieldId = (isset($field['fieldId']) ? $field['fieldId'] : null);
            if ($fieldId === null)
                throw new SignatureFormatError('Premature end of signature', 6);
            /* Determine field name and size */
            if (!array_key_exists($fieldId, self::$fieldIds)) {
                /* Guess field size, but leave unrecognized */
                $fieldTypeDef = [
                    'type' => ($t = self::$fieldIds[$fieldId & 0xC0]['type']),
                    'name' => sprintf('%s%02x', $t, $i)
                ];
            } else
                $fieldTypeDef = self::$fieldIds[$fieldId];
            /* Read value */
            switch ($fieldTypeDef['type']) {
                case 'uchar':
                    $field = @unpack('Cx/Cv', $signature);
                    $data[$fieldTypeDef['name']] = $v = (isset($field['v']) ? $field['v'] : null);
                    if ($v === null)
                        throw new SignatureFormatError('Premature end of signature');
                    $signature = substr($signature, 2);
                    break;
                case 'ushort':
                    $field = @unpack('Cx/nv', $signature);
                    $data[$fieldTypeDef['name']] = $v = (isset($field['v']) ? $field['v'] : null);
                    if ($v === null)
                        throw new SignatureFormatError('Premature end of signature');
                    $signature = substr($signature, 3);
                    break;
                case 'ulong':
                    $field = @unpack('Cx/Nv', $signature);
                    $data[$fieldTypeDef['name']] = $v = (isset($field['v']) ? $field['v'] : null);
                    if ($v === null)
                        throw new SignatureFormatError('Premature end of signature');
                    $signature = substr($signature, 5);
                    break;
                case 'string':
                    $field = unpack('Cx/nl', $signature);
                    $length =  (isset($field['l']) ? $field['l'] : null);
                    if ($length === null)
                        throw new SignatureFormatError('Premature end of signature');
                    if ($length & 0x8000) {
                        /* For future use */
                        $length = ($length & 0xFF);
                    }
                    $data[$fieldTypeDef['name']] = $v = substr($signature, 3, $length);
                    if (strlen($v) !== $length)
                        throw new SignatureFormatError('Premature end of signature');
                    $signature = substr($signature, 3 + $length);
                    break;
                default:
                    throw new SignatureFormatError('Unsupported variable type');
            }
        }
        unset($data['fieldNum']);
        return $data;
    }

    /**
     * Parse signature version 3
     */
    protected static function parseResult3($signature) {
        $originalSignature = $signature;
        $signature = self::fromBase64($signature, true);
        if (empty($signature))
            throw new SignatureFormatError('Not a valid base64 signature payload', 4);
        $data1 = @unpack('Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength', $signature);
        if ($data1['version'] !== 3)
            throw new SignatureVersionError('Signature version not supported', 5);
        if ($data1['requestTime'] > time())
            throw new SignatureFormatError('Decoded timestamp is in the future', 6);
        if ($data1['signatureTime'] > time())
            throw new SignatureFormatError('Decoded signature timestamp is in the future', 7);
        $data1['masterToken'] = substr($signature, 12, $data1['masterTokenLength']);
        if (($s1 = strlen($data1['masterToken'])) != ($s2 = $data1['masterTokenLength']))
            throw new SignatureFormatError('Master token length mismatch (' . $s1 . ' / ' . $s2 . ')', 8);
        $data2 = unpack('CcustomerSignType/ncustomerTokenLength', substr($signature, 12 + $data1['masterTokenLength']));
        $data2['customerToken'] = substr($signature, 15 + $data1['masterTokenLength'], $data2['customerTokenLength']);
        if (strlen($data2['customerToken']) != $data2['customerTokenLength'])
            throw new SignatureFormatError('Customer token length mismatch', 9);
        return ($data1 + $data2);
    }

    public static function parseResult5($signature, $key)
    {
        $payload = base64_decode(strtr($signature, ['-' => '+', '_' => '/']));
        if (strlen($payload) <= self::HEADER_LENGTH) {
            throw new SignatureError('Malformed signature', 1);
        }

        if (version_compare(PHP_VERSION, '5.6.40') <= 0) {
            $data = unpack('Cversion/nlength/Nzone_id_high/Nzone_id_low', $payload);
            $zoneId = $data['zone_id_low'] | ($data['zone_id_high'] << 32);
        } else {
            $data = unpack('Cversion/nlength/Jzone_id', $payload);
            $zoneId = $data['zone_id'];
        }
        $version = $data['version'];
        $length = $data['length'];
        if ($version !== self::VERSION) {
            throw new SignatureVersionError('Signature version not supported', 5);
        }
        $payload = substr($payload, self::HEADER_LENGTH, $length);
        if (strlen($payload) < $length) {
            throw new SignatureError('Truncated signature payload', 3);
        }
        $lengths = ['iv' => openssl_cipher_iv_length(self::ENCRYPTION_METHOD)];
        if (strlen($payload) < (2 + array_sum($lengths))) {
            throw new \RuntimeException('Premature data end');
        }
        $result = unpack('vmethod', self::eat($payload, 2));
        foreach ($lengths as $k => $length) {
            $result[$k] = self::eat($payload, $length);
        }
        if ($result['method'] != self::METHOD) {
            throw new \RuntimeException('Unrecognized payload', 1);
        }
        if (is_callable($key)) {
            $key = $key($zoneId);
        } else if (is_array($key)) {
            $key = $key[$zoneId];
        } else if (!is_string($key)) {
            throw new \InvalidArgumentException('Key value not recognized');
        }
        $decrypted = openssl_decrypt(
            $payload,
            self::ENCRYPTION_METHOD,
            (self::$useRawHmacKey ? $key : self::fromBase64($key)),
            OPENSSL_RAW_DATA,
            $result['iv']
        );
        if ($decrypted === false) {
            throw new \RuntimeException('Decryption error');
        }
        $serializationType = substr($decrypted, 0, 1);
        $decrypted =  substr($decrypted, 1);
        switch ($serializationType) {
            case self::SERIALIZATION_S:
                if (version_compare(PHP_VERSION, '7.0.0') < 0) {
                    $structure = unserialize($decrypted);
                } else {
                    $structure = unserialize($decrypted, ['allowed_classes' => false]);
                }
                break;
            case self::SERIALIZATION_H:
                $structure = null;
                parse_str($decrypted, $structure);
                break;
            default:
                throw new \RuntimeException('Unsupported serialization type');
        }
        if ($structure === false) {
            throw new \RuntimeException('Deserialization error');
        }
        return $structure;
    }

    public static function eat(&$source, $length)
    {
        if (strlen($source) < $length) {
            throw new \RangeException('Not enough data to consume');
        }
        $result = substr($source, 0, $length);
        $source = substr($source, $length);
        return $result;
    }

    protected static function checkResult($result, $ipAddresses, $userAgent)
    {
        $matchingIp = null;
        foreach ($ipAddresses as $ipAddress) {
            $nIpAddress = inet_pton($ipAddress);
            if ((inet_pton($result['ipv4.ip']) === $nIpAddress) || (inet_pton($result['ipv6.ip']) === $nIpAddress)) {
                $matchingIp = $ipAddress;
                break;
            }
        }
        if ($matchingIp === null) {
            throw new SignatureVerifyError('Signature IP mismatch', 13);
        }
        if (strcmp($result['b.ua'] ?? $result['userAgent'], $userAgent) !== 0) {
            throw new SignatureVerifyError('Signature user agent mismatch', 14);
        }
    }

}
