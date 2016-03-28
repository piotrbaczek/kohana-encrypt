<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * MCRYPT encryption
 * Exact copy of Kohana_Encrypt
 */
class Core_Encrypt_Mcrypt extends Core_Engine {

	private $_mode;
	private $_rand = NULL;

	/**
	 * Constructor
	 * @throws Kohana_Exception
	 */
	public function __construct()
	{
		$config_reader = new Kohana_Config_File_Reader('certificates');

		$config_reader->load('encryption');

		Kohana::$config->attach($config_reader);
		
		$config = Kohana::$config->load('encryption.mcrypt');
		
		if (!isset($config['key']))
		{
			throw new Kohana_Exception(__CLASS__ . ' key is not set');
		}

		if (!isset($config['mode']))
		{
			// Add the default mode
			$config['mode'] = MCRYPT_MODE_NOFB;
		}

		if (!isset($config['cipher']))
		{
			// Add the default cipher
			$config['cipher'] = MCRYPT_RIJNDAEL_128;
		}

		$this->_key = (String) $config['key'];
		$this->_cipher = (String) $config['cipher'];
		$this->_mode = (String) $config['mode'];
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
	 * Decrypts given data with key
	 * @param String $ciphertext
	 * @return String
	 */
	public function decode($ciphertext)
	{
		// Convert the data back to binary
		$data = base64_decode($ciphertext, TRUE);

		if (!$data)
		{
			// Invalid base64 data
			return FALSE;
		}

		// Extract the initialization vector from the data
		$iv = substr($data, 0, $this->getIvSize());

		if ($this->getIvSize() !== strlen($iv))
		{
			// The iv is not the expected size
			return FALSE;
		}

		// Remove the iv from the data
		$data = substr($data, $this->getIvSize());

		// Return the decrypted data, trimming the \0 padding bytes from the end of the data
		return rtrim(mcrypt_decrypt($this->_cipher, $this->_key, $data, $this->_mode, $iv), "\0");
	}

	/**
	 * Encrypts data with given key
	 * @param String $message
	 * @return String
	 */
	public function encode($message)
	{
		// Set the rand type if it has not already been set
		if ($this->_rand === NULL)
		{
			if (Kohana::$is_windows)
			{
				// Windows only supports the system random number generator
				$this->_rand = MCRYPT_RAND;
			}
			else
			{
				if (defined('MCRYPT_DEV_URANDOM'))
				{
					// Use /dev/urandom
					$this->_rand = MCRYPT_DEV_URANDOM;
				}
				elseif (defined('MCRYPT_DEV_RANDOM'))
				{
					// Use /dev/random
					$this->_rand = MCRYPT_DEV_RANDOM;
				}
				else
				{
					// Use the system random number generator
					$this->_rand = MCRYPT_RAND;
				}
			}
		}

		if ($this->_rand === MCRYPT_RAND)
		{
			// The system random number generator must always be seeded each
			// time it is used, or it will not produce true random results
			mt_srand();
		}

		// Create a random initialization vector of the proper size for the current cipher
		$iv = mcrypt_create_iv($this->getIvSize(), $this->_rand);

		// Encrypt the data using the configured options and generated iv
		$data = mcrypt_encrypt($this->_cipher, $this->_key, $message, $this->_mode, $iv);

		// Use base64 encoding to convert to a string
		return base64_encode($iv . $data);
	}

}
