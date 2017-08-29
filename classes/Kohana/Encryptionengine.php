<?php

/**
 *
 * @author nzpetter
 */
interface Kohana_Encryptionengine
{

	public function encrypt(String $message);

	public function decrypt(String $ciphertext);
}
