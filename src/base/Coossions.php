<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 05.04.17
 * Time: 20:16
 */

namespace coossions\base;

use coossions\crypt\Encryptor;
use coossions\exceptions\OpenSSLException;

class Coossions implements BaseInterface
{
    private $encryptor = null;

    private $value = '';
    // encryption
    private $cookieExpiration = null;
    private $digestAlgo       = null;
    private $cipherAlgo       = null;
    private $cipherKeylen     = null;

    private $sidLength = 0;

    public function __construct()
    {
        $this->encryptor              = new Encryptor();
        $this->cookieExpiration = $this->encryptor->getExpire();
        $this->digestAlgo       = $this->encryptor->getDigestAlgo();
        $this->cipherAlgo       = $this->encryptor->getCipherAlgo();
        $this->cipherKeylen     = $this->encryptor->getCipherKeylen();
    }

    public function setEncryption(Encryptor $encryptor)
    {
        $this->cookieExpiration = $encryptor->getExpire();
        $this->digestAlgo       = $encryptor->getDigestAlgo();
        $this->cipherAlgo       = $encryptor->getCipherAlgo();
        $this->cipherKeylen     = $encryptor->getCipherKeylen();
        // if user changed cipher algo
        $this->cipherKeylen = openssl_cipher_iv_length($encryptor->getCipherAlgo());
    }

    /**
     * Close the session
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.close.php
     * @return bool <p>
     *        The return value (usually TRUE on success, FALSE on failure).
     *        Note this value is returned internally to PHP for processing.
     *        </p>
     * @since 5.4.0
     */
    public function close()
    {
        return true;
    }

    /**
     * Destroy a session
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.destroy.php
     *
     * @param string $sid The session ID being destroyed.
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function destroy($sid)
    {
        setcookie($sid, '', time() - 3600);
        setcookie($sid, '', time() - 3600, '/');

        return true;
    }

    /**
     * Cleanup old sessions
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.gc.php
     *
     * @param int $maxlifetime <p>
     *                         Sessions that have not updated for
     *                         the last maxlifetime seconds will be removed.
     *                         </p>
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function gc($maxlifetime)
    {
        return true;
    }

    /**
     * Initialize session
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.open.php
     *
     * @param string $save_path  The path where to store/retrieve the session.
     * @param string $sid The session id.
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function open($save_path, $sid)
    {
        $this->cipherKeylen = openssl_cipher_iv_length($this->cipherAlgo);
        $this->sidLength = strlen($sid);
        return true;
    }

    /**
     * Read session data
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.read.php
     *
     * @param string $session_id The session id to read data for.
     *
     * @return string <p>
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function read($session_id)
    {
        return $this->value;
    }

    /**
     * Write session data
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.write.php
     *
     * @param string $session_id   The session id.
     * @param string $session_data <p>
     *                             The encoded session data. This data is the
     *                             result of the PHP internally encoding
     *                             the $_SESSION superglobal to a serialized
     *                             string and passing it as this parameter.
     *                             Please note sessions use an alternative serialization method.
     *                             </p>
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function write($session_id, $session_data)
    {
        return true;
    }

    /**
     * Encrypt a string.
     *
     * @param  string $in  String to encrypt.
     * @param  string $key Encryption key.
     *
     * @return string The encrypted string.
     * @throws \Exception
     */
    public function encryptString(string $in, string $key)
    {
        // Build an initialisation vector
        $iv = mcrypt_create_iv($this->cipherKeylen, MCRYPT_DEV_URANDOM);
        // Hash the key
        $keyhash = openssl_digest($key, $this->digestAlgo, true);
        // and encrypt
        $opts      = OPENSSL_RAW_DATA;
        $encrypted = openssl_encrypt($in, $this->cipherAlgo, $keyhash, $opts, $iv);
        if ($encrypted === false) {
            throw new OpenSSLException('Cryptor::encryptString() - Encryption failed: ' . openssl_error_string());
        }
        // The result comprises the IV and encrypted data
        $res = $iv . $encrypted;

        return base64_encode($res);
    }

    /**
     * Decrypt a string.
     *
     * @param  string $in  String to decrypt.
     * @param  string $key Decryption key.
     *
     * @return string The decrypted string.
     * @throws OpenSSLException
     *
     */
    public function decryptString(string $in, string $key)
    {
        $raw = base64_decode($in);

        // and do an integrity check on the size.
        if (strlen($raw) < $this->cipherKeylen) {
            throw new OpenSSLException(
                'Cryptor::decryptString() - ' .
                'data length ' . strlen($raw) . " is less than iv length {$this->cipherKeylen}"
            );
        }
        // Extract the initialisation vector and encrypted data
        $iv  = substr($raw, 0, $this->cipherKeylen);
        $raw = substr($raw, $this->cipherKeylen);
        // Hash the key
        $keyhash = openssl_digest($key, $this->digestAlgo, true);
        // and decrypt.
        $opts = OPENSSL_RAW_DATA;
        $res  = openssl_decrypt($raw, $this->digestAlgo, $keyhash, $opts, $iv);
        if ($res === false) {
            throw new OpenSSLException('Cryptor::decryptString - decryption failed: ' . openssl_error_string());
        }

        return $res;
    }
}