<?php

echo '<?php

defined(\'SYSPATH\') or die(\'No direct script access.\');';
echo "\r\n";
echo "return array(
	'default' => array(
		'type' => " . 'Encrypt::ENGINE_AES' . ",
		'secretkey' => '$aes_secretkey',
		'signingkey' => '$aes_signingkey',
		'hash' => 'sha512'
	),
	'secondary' => array(
		'type' => " . 'Encrypt::ENGINE_RSA' . ",
		'secretkey' => '$rsa_secretkey',
		'hash' => 'sha512',
		'public' => '$rsa_publickey',
		'private' => '$rsa_privatekey',
		'certificate' => '$rsa_certificate'
	)
);";
