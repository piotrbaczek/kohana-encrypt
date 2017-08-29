<?php

/**
 * @see https://github.com/illuminate/encryption/blob/master/Encrypter.php
 */
abstract class Kohana_Engine_Engine
{

	/**
	 * Allowed hashes
	 */
	const ALLOWED_HASHES = ['sha256', 'sha384', 'sha512'];

	/**
	 * Encoder
	 */
	protected $_encoder;

	/**
	 * Decoder
	 */
	protected $_decoder;

	/**
	 * Secret key length
	 * @var int
	 */
	protected $_secret_key_length;

	/**
	 * Signing key - used for generating signatures with AES
	 * @var String
	 */
	protected $_signing_key;

	/**
	 * Length of signing key
	 * @var int
	 */
	protected $_signing_key_length;

	/**
	 * Hashing function name
	 * @var String
	 */
	protected $_hash;

	/**
	 * Name of the config
	 * @var type String
	 */
	protected $_name;

	/**
	 * Encryption function
	 * @param String $message Message
	 * @return String;
	 */
	abstract public function encrypt(String $message): String;

	/**
	 * Decryption function
	 * @param String $ciphertext Ciphertext
	 * @return String
	 */
	abstract public function decrypt(String $ciphertext): String;

	/**
	 * Returns payload from ciphertext
	 * @param String $payload Payload
	 * @return array
	 */
	abstract protected function get_payload(String $payload): array;

	/**
	 * Checks if payload is valid
	 * @param array $payload Array with payload
	 * @return bool
	 */
	abstract protected function invalid_payload(array $payload): bool;

	/**
	 * Checks if the signature is valid
	 * @param array $payload Payload
	 * return bool
	 */
	abstract protected function valid_signature(array $payload): bool;

	/**
	 * Checks if the key is supported
	 * @param String $key Encryption key
	 * @param int $forced_value Flag if specific length is required
	 * @return int
	 */
	abstract public static function supported($key, int $forced_value = NULL): int;

	/**
	 * Get key length
	 * @param String $key Key
	 * @return int
	 */
	public static function key_length($key): int
	{
		return mb_strlen($key, '8bit');
	}

}
