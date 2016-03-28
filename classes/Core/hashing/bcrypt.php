<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * Bcrypt Hashing scheme
 */
class Core_Hashing_Bcrypt extends Core_Hashing_Engine {

	public function __construct()
	{
		$config = Kohana::$config->load('hashing.bcrypt');

		if (!isset($config['cost']) OR ! is_numeric($config['cost']) OR $config['cost'] < 4 OR $config['cost'] > 31)
		{
			throw new Kohana_Exception(__CLASS__ . ' cost parameter must be set as integer range 4-31');
		}
		else
		{
			$this->_cost = (int) $config['cost'];
		}
	}

	public function hash($password)
	{
		return password_hash($password, PASSWORD_BCRYPT, array(
			'cost' => $this->_cost
		));
	}

	public function verify($password, $hash)
	{
		return password_verify($password, $hash);
	}

	public function needs_rehash($hash)
	{
		return password_needs_rehash($hash, PASSWORD_BCRYPT,array(
			'cost' => $this->_cost
		));
	}

}
