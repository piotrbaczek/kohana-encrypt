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
	 * Factory pattern
	 * Constructor is private
	 */
	private function __construct()
	{
		
	}

}
