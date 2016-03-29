<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * AES-128-CBC and AES-256-CBC port from Laravel 5.2
 * @link https://github.com/laravel/framework/blob/5.2/src/Illuminate/Encryption/Encrypter.php
 * @author Laravel Team
 */
class Core_Encrypt_Openssl extends Core_Encrypt_Engine {

	/**
	 * Use only hashes without collisions
	 */
	const HASHES = array('sha224', 'sha256', 'sha384', 'sha512');

	/**
	 *
	 * @var string hash
	 */
	protected $_hash;

	/**
	 * Constructor
	 * @throws Kohana_Exception
	 */
	public function __construct()
	{
		$config_reader = new Kohana_Config_File_Reader('certificates');

		$config_reader->load('encryption');

		Kohana::$config->attach($config_reader);

		$config = Kohana::$config->load('encryption.openssl');

		if (!isset($config['cipher']))
		{
			throw new Kohana_Exception(__CLASS__ . ' cipher is not set');
		}

		$cipher = (String) $config['cipher'];

		if (!isset($config['hash']) OR ! in_array($config['hash'], self::HASHES))
		{
			throw new Kohana_Exception(__CLASS__ . ' hash must be one of the provided :ciphers', array(
		':ciphers' => self::HASHES
			));
		}

		if (!isset($config['key']))
		{
			throw new Kohana_Exception(__CLASS__ . ' key is not set');
		}
		else
		{
			$key = (String) $config['key'];
			if (substr($key, 0, 7) == 'base64:')
			{
				$key = base64_decode(substr($key, 7));
			}

			if (self::supported($key, $cipher))
			{
				$this->_key = $key;
				$this->_cipher = $cipher;
				$this->_hash = $config['hash'];
			}
			else
			{
				throw new Kohana_Exception('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
			}
		}
	}

	/**
	 * Check if $cipher is supported and $key is of correct length for given cipher
	 * @param String $key
	 * @param String $cipher
	 * @return boolean
	 */
	public static function supported($key, $cipher)
	{
		$length = mb_strlen($key, '8bit');
		return ($cipher === 'AES-128-CBC' && $length === 16) || ($cipher === 'AES-256-CBC' && $length === 32);
	}

	/**
	 * Return IV size for a cipher
	 * @return int
	 */
	protected function getIvSize()
	{
		return 16;
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

	/**
	 * Decodes and splits the result into data, IV and MAC
	 * @param JSON $payload
	 * @return boolean
	 */
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
		$bytes = openssl_random_pseudo_bytes($this->getIvSize());
		$calcMac = hash_hmac($this->_hash, $this->hash($payload['iv'], $payload['value']), $bytes, true);
		return hash_equals(hash_hmac($this->_hash, $payload['mac'], $bytes, true), $calcMac);
	}

	/**
	 * Encrypts data with given key
	 * @param String $message
	 * @return boolean
	 * @throws Kohana_Exception
	 */
	public function encode($message)
	{
		if (!function_exists('openssl_random_pseudo_bytes'))
		{
			throw new Kohana_Exception('OPENSSL must be installed for ' . __CLASS__ . ' to work. Install it on your machine and try again.');
		}
		$iv = openssl_random_pseudo_bytes($this->getIvSize());
		$value = openssl_encrypt(serialize($message), $this->_cipher, $this->_key, 0, $iv);
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

	/**
	 * Decrypts given data with key
	 * @param String $ciphertext
	 * @return boolean
	 */
	public function decode($ciphertext)
	{
		$payload = $this->getJsonPayload($ciphertext);

		if ($payload === FALSE)
		{
			return FALSE;
		}

		$iv = base64_decode($payload['iv']);
		$decrypted = openssl_decrypt($payload['value'], $this->_cipher, $this->_key, 0, $iv);
		if ($decrypted === false)
		{
			return FALSE;
		}
		return unserialize($decrypted);
	}

}
