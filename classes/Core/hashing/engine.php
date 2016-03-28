<?php

defined('SYSPATH') or die('No direct script access.');

abstract class Core_Hashing_Engine {

	private $_cost;

	abstract public function hash($password);

	abstract public function verify($password, $hash);

	abstract public function needs_rehash($hash);
}
