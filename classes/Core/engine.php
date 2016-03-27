<?php

defined('SYSPATH') or die('No direct script access.');

abstract class Core_Engine {

	private $_key;
	protected $_cipher;

	abstract public function encode($message);

	abstract public function decode($ciphertext);

	abstract protected function getIvSize();
}
