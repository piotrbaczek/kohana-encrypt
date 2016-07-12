<?php

defined('SYSPATH') or die('No direct script access.');

abstract class Core_Encrypt_Engine {

	protected $_key;
	protected $_cipher;

	abstract public function encode($message);

	abstract public function decode($ciphertext);

	abstract protected function getIvSize();
}
