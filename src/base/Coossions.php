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
    const FORMAT_RAW = 0;
    const FORMAT_B64 = 1;
    const FORMAT_HEX = 2;

    private $value = '';
    // encryption
    private $cookieExpiration;
    private $digestAlgo;
    private $cipherAlgo;
    private $cipherKeylen;

    public function __construct()
    {

    }

    public function setEncryption(Encryptor $encryptor)
    {
        $this->cookieExpiration = $encryptor->getExpire();
        $this->digestAlgo       = $encryptor->getDigestAlgo();
        $this->cipherAlgo       = $encryptor->getCipherAlgo();
        $this->cipherKeylen     = $encryptor->getCipherKeylen();
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
     * @param string $session_id The session id.
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function open($save_path, $session_id)
    {

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
     * @param  int    $fmt Optional override for the output encoding. One of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX.
     *
     * @return string The encrypted string.
     * @throws \Exception
     */
    public function encryptString(string $in, string $key, int $fmt = null)
    {
        if ($fmt === null)
        {
            $fmt = $this->format;
        }
        // Build an initialisation vector
        $iv = mcrypt_create_iv($this->iv_num_bytes, MCRYPT_DEV_URANDOM);
        // Hash the key
        $keyhash = openssl_digest($key, $this->digestAlgo, true);
        // and encrypt
        $opts =  OPENSSL_RAW_DATA;
        $encrypted = openssl_encrypt($in, $this->cipherAlgo, $keyhash, $opts, $iv);
        if ($encrypted === false)
        {
            throw new OpenSSLException('Cryptor::encryptString() - Encryption failed: ' . openssl_error_string());
        }
        // The result comprises the IV and encrypted data
        $res = $iv . $encrypted;
        // and format the result if required.
        if ($fmt == self::FORMAT_B64)
        {
            $res = base64_encode($res);
        }
        else if ($fmt == self::FORMAT_HEX)
        {
            $res = unpack('H*', $res)[1];
        }
        return $res;
    }

    /**
     * Decrypt a string.
     *
     * @param  string $in  String to decrypt.
     * @param  string $key Decryption key.
     * @param  int    $fmt Optional override for the input encoding. One of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX.
     *
     * @return string The decrypted string.
     * @throws \Exception
     */
    public function decryptString(string $in, string $key, int $fmt = null)
    {
        if ($fmt === null)
        {
            $fmt = $this->format;
        }
        $raw = $in;
        // Restore the encrypted data if encoded
        if ($fmt == Cryptor::FORMAT_B64)
        {
            $raw = base64_decode($in);
        }
        else if ($fmt == Cryptor::FORMAT_HEX)
        {
            $raw = pack('H*', $in);
        }
        // and do an integrity check on the size.
        if (strlen($raw) < $this->iv_num_bytes)
        {
            throw new OpenSSLException('Cryptor::decryptString() - ' .
                                 'data length ' . strlen($raw) . " is less than iv length {$this->iv_num_bytes}");
        }
        // Extract the initialisation vector and encrypted data
        $iv = substr($raw, 0, $this->iv_num_bytes);
        $raw = substr($raw, $this->iv_num_bytes);
        // Hash the key
        $keyhash = openssl_digest($key, $this->hash_algo, true);
        // and decrypt.
        $opts = OPENSSL_RAW_DATA;
        $res = openssl_decrypt($raw, $this->cipher_algo, $keyhash, $opts, $iv);
        if ($res === false)
        {
            throw new OpenSSLException('Cryptor::decryptString - decryption failed: ' . openssl_error_string());
        }
        return $res;
    }
}