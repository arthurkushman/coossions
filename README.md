# coossions
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/arthurkushman/coossions/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/arthurkushman/coossions/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/arthurkushman/coossions/badges/build.png?b=master)](https://scrutinizer-ci.com/g/arthurkushman/coossions/build-status/master)
[![Code Coverage](https://scrutinizer-ci.com/g/arthurkushman/coossions/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/arthurkushman/coossions/?branch=master)
[![MIT Licence](https://badges.frapsoft.com/os/mit/mit.svg?v=103)](https://opensource.org/licenses/mit-license.php)

Coossions (stands for cookie-sessions) is a php plugin to store sessions in encrypted cookie

## Installation via composer

```zsh
    composer require arthurkushman/coossions
```

## Usage

```php
    $coossions = new CoossionsHandler('your_digest_secrete'); // any secret word
    $coossions->startSession();    
```

And then, as usual, in any code-space - set session global variables: 

```php
    $_SESSION['foo'] = 123;
    $_SESSION['bar'] = 'baz';    
```

Get session global variables:

```php
    echo $_SESSION['foo'] . ' ' . $_SESSION['bar'];    
```

## Details 
 
Session will be written in cookie on client-side with openssl cipher code (in aes-256-ctr cipher algorithm by default) 
and digested with `your_digest_secrete` (in sha256 by default). 
Also, whole message will be merged with hash_hmac, based on salt consisting of dynamic SID + message, 
which will then checked by hash_equals to additionally identify non-fraudulent data stored in cookie.

To create reliable/secure cryptographic signature, it would be better if `your_digest_secrete` will be in both upper/lower case letters and mashed with digits + long enough.  

## Setting custom hash and cryptographic algorithms through DI

Although, there are already set the best known, at the moment, hash and crypto algos - You can set Your preferable ones:

```php
        $coossions = new CoossionsHandler('your_digest_secrete');
        
        $encryptor = new Encryptor('your_digest_secrete');
        $encryptor->setDigestAlgo('sha512'); // defaults to sha256
        $encryptor->setCipherAlgo('aes-128-ctr'); // defaults to aes-256-ctr
        $coossions->setEncryption($encryptor);
        
        $coossions->startSession();        
```

## Performance 

Tested performance of write/read 2 $_SESSION vars (3 symbols long int/string): 
 
- write avg time 6-8 microseconds
- read avg time 5-7 microseconds 