<?php

defined('SYSPATH') or die('No direct script access.');
echo '<?php

defined(\'SYSPATH\') or die(\'No direct script access.\');';
echo "\r\n";
echo "return array(
	'openssl' => array(
		'hash' => 'sha512',
		'cipher' => 'AES-256-CBC',
		'key' => '$aes_password'
	),
	'rsa' => array(
		'key' => '$rsa_password',
		'hash' => 'sha512',
		'public' => '$rsa_publickey',
		'private' => '$rsa_privatekey'
	)
);";
