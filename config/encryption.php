<?php

return array(
	'default' => array(
		'type' => Encryption::ENGINE_AES,
		'secretkey' => NULL,
		'signingkey' => NULL,
		'hash' => 'sha512'
	),
	'secondary' => array(
		'type' => Encryption::ENGINE_RSA,
		'secretkey' => NULL,
		'hash' => 'sha512',
		'public' => NULL,
		'private' => NULL
	)
);
