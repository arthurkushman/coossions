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

    const MIN_LEN_PER_COOKIE = 6;
    const COOKIE_SIZE        = 4096;
    const PACK_CODE          = 'V';
    const META_DATA_SIZE     = 4;

    /**
     * Encrypt a string.
     *
     * @param  string $in  String to encrypt.
     * @param  string $key Encryption key.
     *
     * @return string The encrypted string.
     * @throws \Exception
     */
    function encryptString(string $in, string $key);

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