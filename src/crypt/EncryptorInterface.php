<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 08.04.17
 * Time: 11:32
 */

namespace coossions\crypt;


use coossions\exceptions\OpenSSLException;

interface EncryptorInterface
{
    const MIN_LEN_PER_COOKIE = 6;
    const COOKIE_SIZE        = 4096;

    /**
     * Encrypt a string.
     *
     * @param  string $in String to encrypt.
     * @param  string $key Encryption key.
     *
     * @param string $sid
     * @return string The encrypted string.
     * @throws OpenSSLException
     */
    public function encryptString(string $in, string $key, string $sid): string;

    /**
     * Decrypt a string.
     *
     * @param  string $in  String to decrypt.
     * @param  string $key Decryption key.
     *
     * @param string  $sid Session id
     *
     * @return string The decrypted string.
     * @throws OpenSSLException
     */
    public function decryptString(string $in, string $key, string $sid): string;
}