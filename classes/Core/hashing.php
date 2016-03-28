<?php

defined('SYSPATH') or die('No direct script access.');

abstract class Core_Hashing {

	const ENGINE_BCRYPT = 'bcrypt';

	public static function instance($engine = self::ENGINE_BCRYPT)
	{
		$class = 'Core_Hashing_' . $engine;
		return new $class();
	}

	private function __construct()
	{
		
	}

}
