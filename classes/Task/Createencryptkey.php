<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * Generates config file for the kohana-encrypt module
 * Placing encryption.php in APPPATH/config
 * @author Piotr Gołasz <pgolasz@gmail.com>
 */
class Task_Createencryptkey extends Minion_Task {

	protected function _execute(array $params)
	{
		try
		{
			if (!class_exists('phpseclib/Crypt/RSA'))
			{
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'RSA');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Math', 'BigInteger');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'Hash');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'Random');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'Base');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'DES');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/Crypt', 'TripleDES');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/File', 'ASN1');
				include_once Kohana::find_file('vendor/phpseclib/phpseclib/phpseclib/File', 'X509');
			}

			Minion_CLI::write('Creating RSA and AES encryption/decryption keys');

			if (!class_exists('phpseclib\Crypt\RSA'))
			{
				Minion_CLI::write('phpseclib not found. You have to composer install in this module.');
			}
			else
			{
				Minion_CLI::write('Creating RSA encryption/decryption keys');
				$length = (int) Minion_CLI::read('Type length in bits of RSA key:', array(2048, 4096));

				Minion_CLI::wait(2, TRUE);

				$rsa_secretkey = $this->RandomString(32);

				$rsa = new \phpseclib\Crypt\RSA();
				$rsa->setPassword($rsa_secretkey);

				extract($rsa->createKey($length));

				$rsa_private = new \phpseclib\Crypt\RSA();
				$rsa_private->setPassword($rsa_secretkey);
				$rsa_private->loadKey($privatekey);
				$privatekey = $rsa_private->getPrivateKey(\phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1);

				$rsa_public = new \phpseclib\Crypt\RSA();
				$rsa_public->loadKey($publickey);
				$publickey = $rsa_public->getPublicKey(\phpseclib\Crypt\RSA::PUBLIC_FORMAT_PKCS1);

				Minion_CLI::write('RSA private key password:');
				Minion_CLI::write($rsa_secretkey);
				Minion_CLI::write('RSA publickey:');
				Minion_CLI::write($publickey);
				Minion_CLI::write('RSA private key:');
				Minion_CLI::write($privatekey);

				Minion_CLI::write('Creating certificate:');

				Minion_CLI::wait(2, TRUE);

				$subject = new \phpseclib\File\X509();
				$dn_prop_idatorganization = Minion_CLI::read('Type your organization name ...');
				$subject->setDNProp('id-at-organizationName', $dn_prop_idatorganization);
				$subject->setDNProp('name', $dn_prop_idatorganization);

				$dn_prop_email = Minion_CLI::read('Type your e-mail ...');
				$subject->setDNProp('emailaddress', $dn_prop_email);

				$dn_prop_postcode = Minion_CLI::read('Type your postcode ...');
				$subject->setDNProp('postalcode', $dn_prop_postcode);

				$dn_prop_state = Minion_CLI::read('Type your state/province ...');
				$subject->setDNProp('state', $dn_prop_state);

				$dn_prop_address = Minion_CLI::read('Type your address ...');
				$subject->setDNProp('streetaddress', $dn_prop_address);
				$subject->setPublicKey($rsa_public);

				$subject->setDNProp('id-at-serialNumber', hash('sha512', $dn_prop_idatorganization . Text::random(NULL, 24)));

				$issuer = new \phpseclib\File\X509();
				$issuer->setPrivateKey($rsa_private);
				$issuer->setDN($subject->getDN());

				$x509 = new \phpseclib\File\X509();
				$x509->setStartDate(date('Y-m-d H:i:s'));
				$x509->setEndDate(date('Y-m-d H:i:s', strtotime('+1 year')));
				$result = $x509->sign($issuer, $subject, 'sha512WithRSAEncryption');

				$rsa_certificate = $x509->saveX509($result);

				Minion_CLI::write('RSA certificate:');
				Minion_CLI::write($rsa_certificate);

				Minion_CLI::write('Creating AES key.');

				Minion_CLI::wait(2, TRUE);

				$aes_secretkey = $this->RandomString(32);

				$aes_signingkey = $this->RandomString(32);

				Minion_CLI::write('AES keys created.');
				Minion_CLI::write('AES secret key: ' . $aes_secretkey);
				Minion_CLI::write('AES signing key: ' . $aes_signingkey);

				$view = View::factory('createencryptkey')
						->bind('aes_secretkey', $aes_secretkey)
						->bind('aes_signingkey', $aes_signingkey)
						->bind('rsa_secretkey', $rsa_secretkey)
						->bind('rsa_publickey', $publickey)
						->bind('rsa_privatekey', $privatekey)
						->bind('rsa_certificate', $rsa_certificate)
						->render();

				$put_contents = file_put_contents(APPPATH . 'config' . DIRECTORY_SEPARATOR . 'encryption.php', $view);

				if ($put_contents !== FALSE)
				{
					Minion_CLI::write('Saved both keys to: ' . APPPATH . 'config' . DIRECTORY_SEPARATOR . 'encryption.php');
				}
				else
				{
					Minion_CLI::write('Could not save keys to APPPATH/config, most likely permissions issue.');
				}
			}
		}
		catch (Exception $ex)
		{
			if (get_class($ex) == 'ErrorException' AND $ex->getCode() == 2)
			{
				Minion_CLI::write('Class PHPSECLIB not found. You have to composer install in encrypt module.');
			}
			else
			{
				Minion_CLI::write('General error occured: ' . $ex->getMessage());
			}
		}
	}

	/**
	 * Generates random non-cryptographicly-secure strings for key passwords
	 * @author Piotr Gołasz <pgolasz@gmail.com>
	 * @param integer $length
	 * @return string
	 */
	private function RandomString($length = 10)
	{
		// https://www.owasp.org/index.php/Password_special_characters
		// Use all US-keyboard characters (without single quote that messes up with string lengths)
		return Text::random('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%()*+,-./:;<=>?@[]^_`{|}~', $length);
	}

}
