<?php

namespace coossions\crypt;

use coossions\exceptions\OpenSSLException;

class Encryptor implements EncryptorInterface
{
    /** @var string $secret the secret user key */
    protected $secret = '';

    protected $expire       = 2592000; // 30 days
    protected $digestAlgo   = 'sha256';
    protected $cipherAlgo   = 'aes-256-ctr';
    protected $cipherIvLen  = 32; // aes-256-ctr length
    protected $digestLength = 64; // sha256 length

    private function hashesEqual(string $digest, string $message, string $sid)
    {
        return hash_equals(
            hash_hmac($this->digestAlgo, $sid . $message, $this->secret, true),
            $digest
        );
    }

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
    public function encryptString(string $in, string $key, string $sid)
    {
        // Build an initialisation vector
        $iv = random_bytes($this->cipherIvLen);
        // Hash the key
        $keyHash   = openssl_digest($key, $this->digestAlgo, true);
        $encrypted = openssl_encrypt($in, $this->cipherAlgo, $keyHash, OPENSSL_RAW_DATA, $iv);
        if (false === $encrypted) {
            throw new OpenSSLException('encryptString() - Encryption failed: ' . openssl_error_string());
        }
        // The result comprises the IV and encrypted data
        $res = pack(self::PACK_CODE, time() + $this->expire) . $iv . $encrypted;

        $msg = base64_encode($res);
        $digest = hash_hmac($this->digestAlgo, $sid . $msg, $this->secret, true);
        return base64_encode($digest . $msg);
    }

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
    public function decryptString(string $in, string $key, string $sid)
    {
        $raw = base64_decode($in);

        // and do an integrity check on the size.
        if (strlen($raw) < $this->cipherIvLen) {
            throw new OpenSSLException(
                'decryptString() - data length ' . strlen($raw) . ' is less than iv length ' . $this->cipherIvLen
            );
        }

        $digest = substr($raw, 0, $this->digestLength);
        if (false === $digest) {
            return '';
        }
        $msg = substr($raw, $this->digestLength);
        if (false === $msg) {
            return '';
        }

        if ($this->hashesEqual($digest, $msg, $sid) === false) {
            return '';
        }

        $validTill = substr($msg, 0, self::META_DATA_SIZE);
        $exp       = unpack(self::PACK_CODE, $validTill)[1];
        if (time() > $exp) {
            return '';
        }

        // 2nd base64_decode for message pack(self::PACK_CODE, time() + $this->cookieExpTime) . $iv . $encrypted
        $msg = base64_decode($msg);
        // Extract the initialisation vector and encrypted data
        $iv  = substr($msg, 0, $this->cipherIvLen);
        $raw = substr($msg, $this->cipherIvLen);
        // Hash the key
        $keyHash = openssl_digest($key, $this->digestAlgo, true);
        $res     = openssl_decrypt($raw, $this->digestAlgo, $keyHash, OPENSSL_RAW_DATA, $iv);
        if (false === $res) {
            throw new OpenSSLException('decryptString - decryption failed: ' . openssl_error_string());
        }

        return $res;
    }

    /**
     * @param int $expire
     */
    public function setExpire($expire)
    {
        $this->expire = $expire;
    }

    /**
     * @return int
     */
    public function getExpire()
    {
        return $this->expire;
    }

    /**
     * @param string $digestAlgo
     */
    public function setDigestAlgo($digestAlgo)
    {
        $this->digestAlgo = $digestAlgo;
    }

    /**
     * @return string
     */
    public function getDigestAlgo()
    {
        return $this->digestAlgo;
    }

    /**
     * @param string $cipherAlgo
     */
    public function setCipherAlgo($cipherAlgo)
    {
        $this->cipherAlgo = $cipherAlgo;
    }

    /**
     * @return string
     */
    public function getCipherAlgo()
    {
        return $this->cipherAlgo;
    }

    /**
     * @param int $cipherIvLen
     */
    public function setCipherIvLen($cipherIvLen)
    {
        $this->cipherIvLen = $cipherIvLen;
    }

    /**
     * @return int
     */
    public function getCipherIvLen()
    {
        return $this->cipherIvLen;
    }

}