<?php

/**
 * Encryption class
 * @author Piotr Gołasz <pgolasz@gmail.com>
 */
class Kohana_Encrypt
{

	/**
	 * Version number
	 */
	CONST VERSION = '1.0.3';

	/**
	 * Available Engines
	 */
	const ENGINE_AES = 'aes';
	const ENGINE_RSA = 'rsa';

	/**
	 * @var  string  default instance name
	 */
	public static $default = 'default';

	/**
	 * @var  array  Encrypt class instances
	 */
	public static $instances = array();

	/**
	 * Encoder
	 * @var phpseclib\Crypt\RSA or phpseclib\Crypt\AES 
	 */
	private $_encoder;

	/**
	 * Decoder
	 * @var phpseclib\Crypt\RSA 
	 */
	private $_decoder;

	/**
	 * Secret key length
	 * @var integer
	 */
	private $_secret_key_length;

	/**
	 * Signing key - used for generating signatures with AES
	 * @var string
	 */
	private $_signing_key;

	/**
	 * Length of signing key
	 * @var integer
	 */
	private $_signing_key_length;

	/**
	 * Hashing function name
	 * @var string
	 */
	private $_hash;

	/**
	 * Create instance of encryption class
	 * @return \class
	 */
	public static function instance($name = NULL)
	{
		if (is_null($name))
		{
			$name = self::$default;
		}

		$config = Kohana::$config->load('encrypt')->$name;

		if (!isset(self::$instances[$name]))
		{
			$class = 'Kohana_Engine_' . Text::ucfirst($config['type']);

			self::$instances[$name] = new $class($name);
		}

		return self::$instances[$name];
	}

	/**
	 * Constructor is private
	 * @author Piotr Gołasz <pgolasz@gmail.com>
	 */
	private function __construct($name = NULL)
	{

		if (!class_exists('phpseclib\Crypt\RSA'))
		{
			throw new Kohana_Exception('phpseclib/phpseclib is required');
		}

		$config = Kohana::$config->load('encrypt')->$name;

		var_dump($config);
		die();

//		if ($config['type'] == self::ENGINE_AES)
//		{
//			$hash = $config['hash'];
//			if (!in_array($hash, array('sha256', 'sha384', 'sha512')))
//			{
//				$this->_hash = 'sha512';
//			}
//			else
//			{
//				$this->_hash = $hash;
//			}
//
//			$this->_secret_key_length = self::supported($config['secretkey'], $config['type']);
//			if ($this->_secret_key_length > 0)
//			{
//				$this->_encoder = new phpseclib\Crypt\AES(\phpseclib\Crypt\AES::MODE_CBC);
//				$this->_encoder->setPassword($config['secretkey'], 'pbkdf2', $this->_hash, NULL, 4096);
//				$this->_encoder->setPreferredEngine(\phpseclib\Crypt\AES::ENGINE_OPENSSL);
//				$this->_encoder->setKeyLength($this->_secret_key_length * 8);
//			}
//			else
//			{
//				throw new Kohana_Exception('Secret key for AES must be 16 or 32 characters long, provided one is :long long.', array(
//			':long' => self::key_length($config['secretkey'])
//				));
//			}
//
//			$this->_signing_key_length = self::supported($config['signingkey'], $config['type'], 32);
//			if ($this->_signing_key_length > 0)
//			{
//				$this->_signing_key = $config['signingkey'];
//			}
//			else
//			{
//				throw new Kohana_Exception('Signing key for AES must be 32 characters long, provided one is :long long.', array(
//			':long' => self::key_length($config['signingkey'])
//				));
//			}
//		}
//		elseif ($config['type'] == self::ENGINE_RSA)
//		{
//			$hash = $config['hash'];
//			if (!in_array($hash, array('sha256', 'sha384', 'sha512')))
//			{
//				$this->_hash = 'sha512';
//			}
//			else
//			{
//				$this->_hash = $hash;
//			}
//
//			$this->_secret_key_length = $this->key_length($config['secretkey']);
//
//			$this->_encoder = new \phpseclib\Crypt\RSA();
//			$this->_encoder->setPassword($config['secretkey']);
//			if ($this->_encoder->loadKey($config['private']) === false)
//			{
//				throw new Kohana_Exception('Private key is invalid');
//			}
//			$this->_encoder->setHash($this->_hash);
//			$this->_encoder->setMGFHash($this->_hash);
//			$this->_encoder->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
//			$this->_encoder->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PSS);
//
//			$this->_decoder = new \phpseclib\Crypt\RSA();
//			if ($this->_decoder->loadKey($config['public']) === false)
//			{
//				throw new Kohana_Exception('Public key is invalid.');
//			}
//			$this->_decoder->setHash($this->_hash);
//			$this->_decoder->setMGFHash($this->_hash);
//			$this->_decoder->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
//			$this->_decoder->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PSS);
//		}
//		else
//		{
//			throw new Kohana_Exception('type must be one of provided types');
//		}
	}

	/**
	 * Encode data using Encrypt-then-MAC scheme with AES
	 * and Encrypt-then-Sign with RSA
	 * @param String $message
	 * @return boolean
	 */
	public function encrypt(String $message)
	{
		if ($this->_encoder instanceof phpseclib\Crypt\AES)
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
		elseif ($this->_encoder instanceof phpseclib\Crypt\RSA)
		{
			$ciphertext = $this->_encoder->encrypt(serialize($message));
			if ($ciphertext === FALSE)
			{
				return FALSE;
			}

			$value = base64_encode($ciphertext);
			$signature = $this->_encoder->sign($ciphertext);
			if ($signature === FALSE)
			{
				return FALSE;
			}
			$sgn = base64_encode($signature);
			$json = json_encode(compact('value', 'sgn'));
			if (!is_string($json))
			{
				return FALSE;
			}
			return base64_encode($json);
		}
	}

	/**
	 * Verify hmac/signature and decrypt data
	 * @param String $ciphertext
	 * @return boolean
	 */
	public function decrypt(String $ciphertext)
	{
		if ($this->_encoder instanceof phpseclib\Crypt\AES)
		{
			$payload = $this->get_payload_aes($ciphertext);
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
		elseif ($this->_encoder instanceof phpseclib\Crypt\RSA)
		{
			$payload = $this->get_payload_rsa($ciphertext);
			if ($payload === FALSE)
			{
				return FALSE;
			}
			$message = $this->_decoder->decrypt(base64_decode($payload['value']));
			if ($message === FALSE)
			{
				return FALSE;
			}

			return unserialize($message);
		}
	}

	/**
	 * Validates payload with RSA
	 * @param String $ciphertext
	 * @return boolean
	 */
	private function get_payload_rsa(String $ciphertext)
	{
		$payload = json_decode(base64_decode($ciphertext), true);
		if (!$payload || $this->invalid_payload_rsa($payload))
		{
			return FALSE;
		}
		if (!$this->valid_sgn($payload))
		{
			return FALSE;
		}
		return $payload;
	}

	/**
	 * Validates payload with AES
	 * @param String $ciphertext
	 * @return boolean
	 */
	private function get_payload_aes(String $ciphertext)
	{
		$payload = json_decode(base64_decode($ciphertext), true);
		if (!$payload || $this->invalid_payload_aes($payload))
		{
			return FALSE;
		}
		if (!$this->valid_mac($payload))
		{
			return FALSE;
		}
		return $payload;
	}

	/**
	 * Validates payload structure with AES
	 * @param Array $payload
	 * @return bool
	 */
	private function invalid_payload_aes(array $payload): bool
	{
		return !is_array($payload) || !isset($payload['iv']) || !isset($payload['value']) || !isset($payload['mac']);
	}

	/**
	 * Validates payload structure with RSA
	 * @param array $payload
	 * @return bool
	 */
	private function invalid_payload_rsa(array $payload): bool
	{
		return !is_array($payload) || !isset($payload['sgn']) || !isset($payload['value']);
	}

	/**
	 * Verifies RSA signature
	 * @param array $payload
	 * @return bool
	 */
	private function valid_sgn(Array $payload): bool
	{
		return $this->_decoder->verify(base64_decode($payload['value']), base64_decode($payload['sgn']));
	}

	/**
	 * Verifies AES hmac signature
	 * @param array $payload
	 * @return bool
	 */
	private function valid_mac(Array $payload): bool
	{
		$bytes = phpseclib\Crypt\Random::string(16);
		$calcMac = hash_hmac($this->_hash, $this->hmac_sign_aes($payload['iv'], $payload['value']), $bytes, true);
		return hash_equals(hash_hmac($this->_hash, $payload['mac'], $bytes, true), $calcMac);
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
	public function __toString()
	{
		return 'Encrypt (' . get_class($this->_encoder) . ')';
	}

}
