<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * AES-128-CBC and AES-256-CBC port from Laravel 5.2
 * using MCRYPT
 * @link https://github.com/laravel/framework/blob/5.2/src/Illuminate/Encryption/Encrypter.php
 * @author Laravel Team
 */
class Core_Encrypt_Mcrypt extends Core_Encrypt_Engine {

	const HASHES = array('sha224', 'sha256', 'sha384', 'sha512');

	private $_mode;

	/**
	 * Constructor
	 * @throws Kohana_Exception
	 */
	public function __construct()
	{
		$config = Kohana::$config->load('encryption.mcrypt');

		if (!isset($config['key']) OR mb_strlen($config['key'], '8bit') != 32)
		{
			throw new Kohana_Exception(__CLASS__ . ' key is not set or has improper length, :length characters key required', array(
		':length' => 32
			));
		}
		else
		{
			$this->_key = (String) $config['key'];
		}

		if (!isset($config['hash']) OR ! in_array($config['hash'], self::HASHES))
		{
			throw new Kohana_Exception(__CLASS__ . ' hash must be one of the provided :ciphers', array(
		':ciphers' => json_encode(self::HASHES)
			));
		}
		else
		{
			$this->_hash = (String) $config['hash'];
		}


		$this->_cipher = MCRYPT_RIJNDAEL_128;
		$this->_mode = MCRYPT_MODE_CBC;
	}

	/**
	 * Returns IV size
	 * @return type
	 */
	protected function getIvSize()
	{
		return mcrypt_get_iv_size($this->_cipher, $this->_mode);
	}

	/**
	 * Hash result with set hash
	 * @param String $iv
	 * @param String $value
	 * @return String
	 */
	protected function hash($iv, $value)
	{
		return hash_hmac($this->_hash, $iv . $value, $this->_key);
	}

	protected function getJsonPayload($payload)
	{
		$payload = json_decode(base64_decode($payload), true);
		// If the payload is not valid JSON or does not have the proper keys set we will
		// assume it is invalid and bail out of the routine since we will not be able
		// to decrypt the given value. We'll also check the MAC for this encryption.
		if (!$payload || $this->invalidPayload($payload))
		{
			return FALSE;
		}
		if (!$this->validMac($payload))
		{
			return FALSE;
		}
		return $payload;
	}

	/**
	 * Check if payload is correct
	 * @param array $data
	 * @return boolean
	 */
	protected function invalidPayload($data)
	{
		return !is_array($data) || !isset($data['iv']) || !isset($data['value']) || !isset($data['mac']);
	}

	/**
	 * Validate MAC for payload
	 * @param String $payload
	 * @return boolean
	 */
	protected function validMac(array $payload)
	{
		$bytes = mcrypt_create_iv($this->getIvSize(), MCRYPT_RAND);
		$calcMac = hash_hmac($this->_hash, $this->hash($payload['iv'], $payload['value']), $bytes, true);
		return hash_equals(hash_hmac($this->_hash, $payload['mac'], $bytes, true), $calcMac);
	}

	/**
	 * Decrypts given data with key
	 * @param String $ciphertext
	 * @return String
	 */
	public function decode($ciphertext)
	{
		$payload = $this->getJsonPayload($ciphertext);

		if ($payload === FALSE)
		{
			return FALSE;
		}

		$iv = base64_decode($payload['iv']);
		$decrypted = rtrim(mcrypt_decrypt($this->_cipher, $this->_key, base64_decode($payload['value']), $this->_mode, $iv), "\0"); //openssl_decrypt($payload['value'], $this->_cipher, $this->_key, 0, $iv);
		if ($decrypted === false)
		{
			return FALSE;
		}
		return unserialize($decrypted);
	}

	/**
	 * Encrypts data with given key
	 * @param String $message
	 * @return String
	 */
	public function encode($message)
	{
		if (!function_exists('mcrypt_create_iv'))
		{
			throw new Kohana_Exception('MCRYPT must be installed for ' . __CLASS__ . ' to work. Install it on your machine and try again.');
		}
		$iv = mcrypt_create_iv($this->getIvSize(), MCRYPT_RAND);
		$value = base64_encode(mcrypt_encrypt($this->_cipher, $this->_key, serialize($message), $this->_mode, $iv));
		if ($value === false)
		{
			return FALSE;
		}
		// Once we have the encrypted value we will go ahead base64_encode the input
		// vector and create the MAC for the encrypted value so we can verify its
		// authenticity. Then, we'll JSON encode the data in a "payload" array.
		$mac = $this->hash($iv = base64_encode($iv), $value);
		$json = json_encode(compact('iv', 'value', 'mac'));
		if (!is_string($json))
		{
			return FALSE;
		}
		return base64_encode($json);
	}

}
