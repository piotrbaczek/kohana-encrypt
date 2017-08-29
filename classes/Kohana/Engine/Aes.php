<?php

/**
 * AES encryption in Kohana
 */
class Kohana_Engine_Aes extends Kohana_Engine_Engine
{

	/**
	 * Kohana_Engine_Aes Constructor
	 * @param String $name Name of the encrypt config
	 * @throws Kohana_Exception
	 */
	public function __construct(String $name)
	{
		$this->_name = $name;

		$config = Kohana::$config->load('encrypt')->{$this->_name};

		$hash = $config['hash'];

		if (!in_array($hash, self::ALLOWED_HASHES))
		{
			$this->_hash = 'sha512';
		}
		else
		{
			$this->_hash = $hash;
		}

		$this->_secret_key_length = self::supported($config['secretkey']);
		if ($this->_secret_key_length > 0)
		{
			$this->_encoder = new phpseclib\Crypt\AES(\phpseclib\Crypt\AES::MODE_CTR);
			$this->_encoder->setPassword($config['secretkey'], 'pbkdf2', $this->_hash, NULL, 4096);
			$this->_encoder->setPreferredEngine(\phpseclib\Crypt\AES::ENGINE_OPENSSL);
			$this->_encoder->setKeyLength($this->_secret_key_length * 8);
		}
		else
		{
			throw new Kohana_Exception('Secret key for AES must be 16 or 32 characters long, provided one is :long long.', array(
		':long' => self::key_length($config['secretkey'])
			));
		}

		$this->_signing_key_length = self::supported($config['signingkey'], 32);
		if ($this->_signing_key_length > 0)
		{
			$this->_signing_key = $config['signingkey'];
		}
		else
		{
			throw new Kohana_Exception('Signing key for AES must be 32 characters long, provided one is :long long.', array(
		':long' => self::key_length($config['signingkey'])
			));
		}
	}

	/**
	 * 
	 * @inheritdoc
	 */
	public function decrypt(String $ciphertext): String
	{
		$payload = $this->get_payload($ciphertext);
		if ($payload === FALSE)
		{
			return FALSE;
		}

		$iv = base64_decode($payload['iv']);
		$this->_encoder->setIV($iv);
		$decrypted = $this->_encoder->decrypt(base64_decode($payload['value']));

		if ($decrypted === false)
		{
			return FALSE;
		}
		return unserialize($decrypted);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	public function encrypt(String $message): String
	{
		$randomIV = phpseclib\Crypt\Random::string(16);
		$this->_encoder->setIV($randomIV);
		$value = base64_encode($this->_encoder->encrypt(serialize($message)));
		$mac = $this->hmac_sign_aes($iv = base64_encode($randomIV), $value);
		$json = json_encode(compact('iv', 'value', 'mac'));
		if (!is_string($json))
		{
			return FALSE;
		}
		return base64_encode($json);
	}

	/**
	 * Generates hmac signature for AES
	 * @param string $iv
	 * @param string $value
	 * @return string
	 */
	private function hmac_sign_aes($iv, $value)
	{
		return hash_hmac($this->_hash, $iv . $value, $this->_signing_key);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	protected function get_payload(String $payload): array
	{
		$payloadArray = json_decode(base64_decode($payload), true);
		if (!$payloadArray || $this->invalid_payload($payloadArray))
		{
			return FALSE;
		}
		if (!$this->valid_signature($payloadArray))
		{
			return FALSE;
		}
		return $payloadArray;
	}

	/**
	 * 
	 * @inheritdoc
	 */
	protected function invalid_payload(array $payload): bool
	{
		return !is_array($payload) || !isset($payload['iv']) || !isset($payload['value']) || !isset($payload['mac']);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	protected function valid_signature(array $payload): bool
	{
		$bytes = phpseclib\Crypt\Random::string(16);
		$calcMac = hash_hmac($this->_hash, $this->hmac_sign_aes($payload['iv'], $payload['value']), $bytes, true);
		return hash_equals(hash_hmac($this->_hash, $payload['mac'], $bytes, true), $calcMac);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	public static function supported($key, int $forced_value = NULL): int
	{
		$length = mb_strlen($key, '8bit');

		return is_null($forced_value) ? ($length === 16 || $length === 32 ? $length : -1) : ($length === $forced_value ? $length : -1);
	}

	/**
	 * Returns name of Engine
	 * @return String
	 */
	public function __toString(): String
	{
		return self::class . '(' . $this->_name . ')';
	}

}
