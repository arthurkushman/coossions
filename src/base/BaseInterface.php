<?php
namespace coossions\base;

use coossions\crypt\Encryptor;
use SessionHandlerInterface;

interface BaseInterface extends SessionHandlerInterface
{
    const SESSION_NAME = 'PHPSESSID';
    const SESSION_PATH = '';

    /**
     * Setter for DI via Encryptor ex. if user wants to override params
     * @param Encryptor $encryptor  Instance of an Encryptor class pre-set with values
     */
    public function setEncryption(Encryptor $encryptor);
}