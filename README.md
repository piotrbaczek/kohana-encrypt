# kohana-encrypt
Encryption module for Kohana 3.2. Port of Laravel Encrypt-then-MAC scheme for encrypting using OPENSSL and MCRYPT and RSA.
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

### Usage
* OPENSSL (AES-256-CBC or AES-128-CBC)
```sh
$encrypt = Encryption::instance();
echo $encrypt->encode('This is my secret');
```
* MCRYPT (AES-256-CBC)
```sh
$encrypt = Encryption::instance(Encryption::ENGINE_MCRYPT);
echo $encrypt->encode('This is my secret');
```
* RSA
```sh
$encrypt = Encryption::instance(Encryption::ENGINE_RSA);
echo $encrypt->encode('This is my secret');
```

If you want to use this as default Encryption in your application,
then add new file applications/classes/encrypt.php containing:

```sh
<?php defined('SYSPATH') or die('No direct access allowed.');

public class Encrypt extends Encryption{}
```

License
----

MIT


**Free Software, Hell Yeah!**
