<?php

return [
	'default' => [
		'type' => Encrypt::ENGINE_AES,
		'secretkey' => NULL,
		'signingkey' => NULL,
		'hash' => 'sha512'
	],
	'secondary' => [
		'type' => Encrypt::ENGINE_RSA,
		'secretkey' => NULL,
		'hash' => 'sha512',
		'public' => NULL,
		'private' => NULL
	]
];
