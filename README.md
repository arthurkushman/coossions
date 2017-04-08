# coossions
Coossions is a php plugin to store sessions in encrypted cookie

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
        $encryptor->setDigestAlgo('sha512');
        $encryptor->setCipherAlgo('aes-256-cfb');
        $coossions->setEncryption($encryptor);
        
        $coossions->startSession();        
```
