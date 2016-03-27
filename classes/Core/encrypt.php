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
	 * Create instance of encryption class
	 * @param String $engine one of Encryption::ENGINE_ constants
	 * @return \class
	 */
	public static function instance($engine = self::ENGINE_OPENSSL)
	{
		$class = 'Core_Encrypt_' . $engine;
		return new $class();
	}

	/**
	 * Constructor is private
	 * @author Piotr Gołasz <piotr.golasz@etendard.pl>
	 */
	private function __construct()
	{
		
	}

}
