<?php namespace AdScore\Client;

/**
 * Example library for validation response signatures from AdScore system
 *
 * @author		Bartosz Derleta <bartosz@derleta.com>
 * @copyright 	AdScore Technologies DMCC [AE]
 * @version 	20200302
 */

class SignatureError extends \Exception {}
class SignatureFormatError extends SignatureError {}
class SignatureCryptError extends SignatureError {}
class SignatureVersionError extends SignatureError {}

class Signature {

	/* CONFIGURATION */
	/* Validity time of full screening performed for visitor */
	protected static $requestExpiry = 21660;
	/* You may prefer to store HMAC keys decoded, this switch will skip base64 decoding of supplied HMAC key */
	protected static $useRawHmacKey = false;

	/* VERSION-SPECIFIC CONSTANTS */
	/* Supported signature types */
	const HASH_SHA256 = 1;
	const SIGN_SHA256 = 2;

	const RESULTS = [
		0 => ['verdict' => 'ok', 'name' => 'Clean'],
		3 => ['verdict' => 'junk', 'name' => 'Junk'],
		6 => ['verdict' => 'proxy', 'name' => 'Proxy'],
		9 => ['verdict' => 'bot', 'name' => 'Bot'],
	];

	const FIELD_IDS = [
		/* ulong fields */
		0x00 => ['name' => 'requestTime', 'type' => 'ulong'],
		0x01 => ['name' => 'signatureTime', 'type' => 'ulong'],
		/* ushort fields */
		0x40 => ['name' => null, 'type' => 'ushort'], /* Reserved for future use */
		/* uchar fields */
		0x80 => ['name' => 'masterSignType', 'type' => 'uchar'],
		0x81 => ['name' => 'customerSignType', 'type' => 'uchar'],
		/* string fields */
		0xC0 => ['name' => 'masterToken', 'type' => 'string'],
		0xC1 => ['name' => 'customerToken', 'type' => 'string'],
		0xC2 => ['name' => 'masterTokenV6', 'type' => 'string'],
		0xC3 => ['name' => 'customerTokenV6', 'type' => 'string']
	];


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
	public static function verify(string $signature, string $key, $ipAddresses, string $userAgent, string $signRole = 'customer') : array {
		if (!is_array($ipAddresses))
			$ipAddresses = [$ipAddresses];
		$result = self::verifyTokens($signature, $key, $ipAddresses, $userAgent, $signRole);
		if (time() - $result['requestTime'] > self::$requestExpiry)
			throw new SignatureError('Signature base expired', 11);
		return $result;
	}

	/**
	 * Set request expiry in seconds from creation (relative)
	 * 
	 * @param	$expiry		Validity period expressed in seconds since request
	 */
	public static function setRequestExpiry(int $expiry) : void {
		self::$requestExpiry = $expiry;
	}

	/**
	 * Verify signature tokens
	 */
	protected static function verifyTokens(string $signature, string $key, array $ipAddresses, string $userAgent, string $signRole = 'customer') : array {
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
			$longIp = ip2long($ipAddress);
			if ($longIp !== false) {
				$ipAddress = long2ip($longIp);
				$token = $data[$signRole . 'Token'];
			} else {
				$ipAddress = inet_ntop(inet_pton($ipAddress));
				$token = $data[$signRole . 'TokenV6'] ?? null;
				if ($token === null)
					continue;
			}
			/* Check all possible results */
			foreach (self::RESULTS as $result => $meta) {
				$signatureBase = self::getBase($result, $data['requestTime'], $data['signatureTime'], $ipAddress, $userAgent);
				switch ($signType) {
					case self::HASH_SHA256 :
						$xToken = self::hashData($signatureBase, self::$useRawHmacKey ? $key : self::fromBase64($key), 'sha256');
						if (hash_equals($xToken, $token))
							return ['verdict' => $meta['verdict'], 'result' => $result, 'ipAddress' => $ipAddress, 'requestTime' => $data['requestTime'], 'signatureTime' => $data['signatureTime']];
						break;
					case self::SIGN_SHA256 :
						$xValid = self::verifyData($signatureBase, $token, $key, 'sha256');
						if ($xValid)
							return ['verdict' => $meta['verdict'], 'result' => $result, 'ipAddress' => $ipAddress, 'requestTime' => $data['requestTime'], 'signatureTime' => $data['signatureTime']];
						break;
					default :
						throw new SignatureError('Unrecognized sign type', 3);
				}
			}
		}
		throw new SignatureError('No verdict matched', 10);
	}

	/**
	 * Decode base64 payload
	 */
	protected static function fromBase64(string $string) : string {
		return base64_decode(strtr($string, ['-' => '+', '_' => '/']));
	}

	/**
	 * Verify signature against recreated source data
	 */
	protected static function verifyData(string $data, string $signature, string $publicKey, string $algorithm = 'sha256') : bool {
		while (openssl_error_string() !== false);
		$result = openssl_verify($data, $signature, $publicKey, $algorithm);
		if ($result === -1)
			throw new SignatureCryptError('OpenSSL verify failed: ' . openssl_error_string());
		return ((bool)$result);
	}

	/**
	 * Hash signature source data
	 */
	protected static function hashData(string $data, string $key, string $algorithm = 'sha256') : string {
		$hash = hash_hmac($algorithm, $data, $key, true);
		if ($hash === false)
			throw new SignatureCryptError('Unsupported hash algorithm: ' . $algorithm);
		return $hash;
	}

	/**
	 * Build a signature source data
	 */
	protected static function getBase(int $result, int $requestTime, int $signatureTime, string $ipAddress, string $userAgent) : string {
		return join("\n", func_get_args());
	}

	/**
	 * Parse signature version 4
	 */
	protected static function parseResult4(string $signature) : array {
		$signature = self::fromBase64($signature, true);
		if ($signature === false)
			throw new SignatureFormatError('Not a valid base64 signature payload', 4);
		$data = unpack('Cversion/CfieldNum', $signature);
		if ($data['version'] !== 4)
			throw new SignatureVersionError('Signature version not supported', 5);
		$signature = substr($signature, 2);
		for ($i = 0; $i < $data['fieldNum']; ++$i) {
			$fieldId = @unpack('CfieldId', $signature)['fieldId'] ?? null;
			if ($fieldId === null)
				throw new SignatureFormatError('Premature end of signature', 6);
			/* Determine field name and size */
			if (!array_key_exists($fieldId, self::FIELD_IDS)) {
				/* Guess field size, but leave unrecognized */
				$fieldTypeDef = [
					'type' => ($t = self::FIELD_IDS[$fieldId & 0xC0]['type']),
					'name' => sprintf('%s%02x', $t, $i)
				];
			} else
				$fieldTypeDef = self::FIELD_IDS[$fieldId];
			/* Read value */
			switch ($fieldTypeDef['type']) {
				case 'uchar':
					$data[$fieldTypeDef['name']] = $v = (@unpack('Cx/Cv', $signature)['v'] ?? null);
					if ($v === null)
						throw new SignatureFormatError('Premature end of signature');
					$signature = substr($signature, 2);
					break;
				case 'ushort':
					$data[$fieldTypeDef['name']] = $v = (@unpack('Cx/nv', $signature)['v'] ?? null);
					if ($v === null)
						throw new SignatureFormatError('Premature end of signature');
					$signature = substr($signature, 3);
					break;
				case 'ulong':
					$data[$fieldTypeDef['name']] = $v = (@unpack('Cx/Nv', $signature)['v'] ?? null);
					if ($v === null)
						throw new SignatureFormatError('Premature end of signature');
					$signature = substr($signature, 5);
					break;
				case 'string':
					$length = (unpack('Cx/nl', $signature)['l'] ?? null);
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
	protected static function parseResult3(string $signature) : array {
		$signature = self::fromBase64($signature, true);
		if ($signature === false)
			throw new SignatureFormatError('Not a valid base64 signature payload', 4);
		$data1 = unpack('Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength', $signature);
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

}
