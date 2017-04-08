<?php
/**
 * Created by ArthurKushman.
 * Date: 05.04.17
 * Time: 20:17
 */

namespace coossions\base;

use SessionHandlerInterface;

interface BaseInterface extends SessionHandlerInterface
{
    const SESSION_NAME = 'PHPSESSID';
    const SESSION_PATH = '';

    /**
     * Encrypt a string.
     *
     * @param  string $in String to encrypt.
     * @param  string $key Encryption key.
     *
     * @param string $sid
     * @return string The encrypted string.
     */
    function encryptString(string $in, string $key, string $sid);

    /**
     * Decrypt a string.
     *
     * @param  string $in  String to decrypt.
     * @param  string $key Decryption key.
     *
     * @param string  $sid
     *
     * @return string The decrypted string.
     */
    function decryptString(string $in, string $key, string $sid);
}