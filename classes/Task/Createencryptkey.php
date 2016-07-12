<?php

defined('SYSPATH') or die('No direct script access.');

class Task_Createencryptkey extends Minion_Task {

	protected function _execute(array $params)
	{
		include_once Kohana::find_file('vendor', 'autoload');

		Minion_CLI::write('Creating RSA and AES encryption/decryption keys');

		if (!class_exists('phpseclib\Crypt\RSA'))
		{
			Minion_CLI::write('phpseclib not found. You have to composer install in this module.');
		}
		else
		{
			Minion_CLI::write('Creating RSA encryption/decryption keys');

			$rsa_password = $this->RandomString(32);

			$rsa = new phpseclib\Crypt\RSA();
			$rsa->setPassword($rsa_password);
			$rsa->setHash('sha512');
			$rsa->setMGFHash('sha512');

			extract($rsa->createKey(2048));

			Minion_CLI::write('password: '.$rsa_password);
			Minion_CLI::write('pubkey: '.$publickey);
			Minion_CLI::write('privkey: '.$privatekey);

			Minion_CLI::write('Creating AES key.');

			$aes_password = $this->RandomString(32);

			Minion_CLI::write('AES key created.');

			$view = View::factory('createencryptkey')
					->bind('aes_password', $aes_password)
					->bind('rsa_password', $rsa_password)
					->bind('rsa_publickey', $publickey)
					->bind('rsa_privatekey', $privatekey)
					->render();

			$put_contents = file_put_contents(APPPATH.'config'.DIRECTORY_SEPARATOR.'encryption.php', $view);

			if ($put_contents !== FALSE)
			{
				Minion_CLI::write('Saved both keys to: '.APPPATH.'config'.DIRECTORY_SEPARATOR.'encryption.php');
			}
			else
			{
				Minion_CLI::write('Could not save keys to APPPATH/config, most likely permissions issue.');
			}
		}
	}

	private function RandomString($length = 10)
	{
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_-+={}[]:"|\\<>?,./~`';
		$charactersLength = strlen($characters);
		$randomString = '';

		for ($i = 0; $i < (int) $length; $i++)
		{
			$randomString .= $characters[rand(0, $charactersLength - 1)];
		}
		return $randomString;
	}

}
