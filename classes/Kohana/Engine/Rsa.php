<?php

/**
 * RSA encryption in Kohana
 */
class Kohana_Engine_Rsa extends Kohana_Engine_Engine
{

	/**
	 * Kohana_Engine_Rsa Constructor
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
			$this->_encoder = new \phpseclib\Crypt\RSA();
			$this->_encoder->setPassword($config['secretkey']);
			if ($this->_encoder->loadKey($config['private']) === false)
			{
				throw new Kohana_Exception('Private key is invalid');
			}
			$this->_encoder->setHash($this->_hash);
			$this->_encoder->setMGFHash($this->_hash);
			$this->_encoder->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
			$this->_encoder->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PSS);

			$this->_decoder = new \phpseclib\Crypt\RSA();
			if ($this->_decoder->loadKey($config['public']) === false)
			{
				throw new Kohana_Exception('Public key is invalid.');
			}
			$this->_decoder->setHash($this->_hash);
			$this->_decoder->setMGFHash($this->_hash);
			$this->_decoder->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
			$this->_decoder->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PSS);
		}
		else
		{
			throw new Kohana_Exception('Secret key for RSA must be 32 characters long, provided one is :long long.', array(
		':long' => self::key_length($config['secretkey'])
			));
		}
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
		return !is_array($payload) || !isset($payload['sgn']) || !isset($payload['value']);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	protected function valid_signature(array $payload): bool
	{
		return $this->_decoder->verify(base64_decode($payload['value']), base64_decode($payload['sgn']));
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
			return '';
		}
		$message = $this->_decoder->decrypt(base64_decode($payload['value']));
		if ($message === FALSE)
		{
			return '';
		}

		return unserialize($message);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	public function encrypt(String $message): String
	{
		$ciphertext = $this->_encoder->encrypt(serialize($message));
		if ($ciphertext === FALSE)
		{
			return '';
		}

		$value = base64_encode($ciphertext);
		$signature = $this->_encoder->sign($ciphertext);
		if ($signature === FALSE)
		{
			return '';
		}
		$sgn = base64_encode($signature);
		$json = json_encode(compact('value', 'sgn'));
		if (!is_string($json))
		{
			return '';
		}
		return base64_encode($json);
	}

	/**
	 * 
	 * @inheritdoc
	 */
	public static function supported($key, int $forced_value = NULL): int
	{
		$length = mb_strlen($key, '8bit');
		return is_null($forced_value) ? ($length === 32 ? $length : -1) : ($length === $forced_value ? $length : -1);
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
