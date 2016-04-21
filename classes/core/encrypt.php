<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * Encryption class
 * @author Piotr Gołasz <pgolasz@gmail.com>
 */
abstract class Core_Encrypt {

	/**
	 * Available Engines
	 */
	const ENGINE_OPENSSL = 'openssl';
	const ENGINE_MCRYPT = 'mcrypt';
	const ENGINE_RSA = 'rsa';

	/**
	 * Create instance of encryption class, returns OPENSSL as default
	 * @param String $engine one of Encryption::ENGINE_ constants
	 * @return \class
	 */
	public static function instance($engine = self::ENGINE_OPENSSL)
	{
		if (in_array($engine, array(self::ENGINE_MCRYPT, self::ENGINE_OPENSSL, self::ENGINE_RSA)))
		{
			$class = 'Core_Encrypt_' . $engine;
			return new $class();
		}
		else
		{
			return new Core_Encrypt_Openssl();
		}
	}

	/**
	 * Constructor is private
	 * @author Piotr Gołasz <pgolasz@gmail.com>
	 */
	private function __construct()
	{
		
	}

}
