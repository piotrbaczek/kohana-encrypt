# kohana-encrypt
Encryption module for Kohana 3.3. Port of Laravel Encrypt-then-MAC scheme for encrypting using OPENSSL (AES and RSA).
Uses AES-256-CBC and AES-128-CBC, and user public and private keys with RSA.

### Installation

```sh
$ cd modules
$ git clone [git-repo-url]
```
Add this line to Kohana::modules in your bootstrap.php:
```sh
'kohana-encrypt' => MODPATH . 'kohana-encrypt'
```
Install phpseclib using composer
```sh
$ composer install
```

Include autoload.php in your bootstrap.php
```
/**
 * Enable composer autoload libraries
 */
require APPPATH . '../vendor/autoload.php';
```

Generate AES and RSA keys for your application
```sh
$ php index.php --uri=task/encyptkeys
```

It's also possible to generate config inside common module of your application
For example if your core classes are located in /modules/custommodule/classes,
then config will be generated in /modules/custom/config
```sh
$ php index.php --uri=task/encyptkeys --module=custommodule
```

### Usage
* OPENSSL (AES-256-CBC or AES-128-CBC)
```sh
$encrypt = Encrypt::instance();
echo $encrypt->encrypt('This is my secret');
```
* RSA
```sh
$encrypt = Encrypt::instance('secondary');
echo $encrypt->encrypt('This is my secret');
```

License
----

MIT


**Free Software, Hell Yeah!**
