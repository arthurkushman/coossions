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

    /**
     * Encryptor constructor.
     * @param string $secret the secret key to be used in openssl_digest
     */
    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    private function hashesEqual(string $digest, string $message, string $sid): bool
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
    public function encryptString(string $in, string $key, string $sid): string
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
        $msg = $iv . $encrypted;
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
    public function decryptString(string $in, string $key, string $sid): string
    {
        $raw = base64_decode($in);

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

        // Extract the initialisation vector and encrypted data
        $iv  = substr($msg, 0, $this->cipherIvLen);
        $raw = substr($msg, $this->cipherIvLen);
        // Hash the key
        $keyHash = openssl_digest($key, $this->digestAlgo, true);
        $res     = openssl_decrypt($raw, $this->cipherAlgo, $keyHash, OPENSSL_RAW_DATA, $iv);
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
    public function getExpire(): int
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
    public function getDigestAlgo(): string
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
    public function getCipherAlgo(): string
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
    public function getCipherIvLen(): int
    {
        return $this->cipherIvLen;
    }

}