<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 05.04.17
 * Time: 20:16
 */

namespace coossions\base;

use coossions\crypt\Encryptor;
use coossions\exceptions\CookieSizeException;
use coossions\exceptions\OpenSSLException;

class Coossions implements BaseInterface
{
    private $encryptor = null;

    private $value = '';
    // encryption
    private $cookieExpTime = null;
    private $digestAlgo    = null;
    private $cipherAlgo    = null;
    private $cipherKeylen  = 32;
    private $cipherIvLen   = 32;

    private $sidLength         = 0;
    private $sessionNameLength = 0;
    private $cookieParams      = [];
    private $digestLength      = 0;

    private $isOpened = false;

    public function __construct()
    {
        $this->encryptor     = new Encryptor();
        $this->cookieExpTime = $this->encryptor->getExpire();
        $this->digestAlgo    = $this->encryptor->getDigestAlgo();
        $this->cipherAlgo    = $this->encryptor->getCipherAlgo();
        $this->cipherKeylen  = $this->encryptor->getCipherKeylen();
        $this->cipherIvLen   = openssl_cipher_iv_length($this->cipherAlgo);
    }

    /**
     * Setter for DI via Encryptor ex. if user wants to override params
     *
     * @param Encryptor $encryptor
     */
    public function setEncryption(Encryptor $encryptor)
    {
        $this->cookieExpTime = $encryptor->getExpire();
        $this->digestAlgo    = $encryptor->getDigestAlgo();
        $this->cipherAlgo    = $encryptor->getCipherAlgo();
        $this->cipherKeylen  = $encryptor->getCipherKeylen();
        // if user changed cipher algo - re-get length
        $this->cipherIvLen = openssl_cipher_iv_length($this->cipherAlgo);
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
     * @param string $savePath The path where to store/retrieve the session.
     * @param string $sid      The session id.
     *
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function open($savePath, $sid)
    {
        $this->cookieParams      = session_get_cookie_params();
        $this->digestLength      = strlen(hash($this->digestAlgo, '', true));
        $this->cipherKeylen      = openssl_cipher_iv_length($this->cipherAlgo);
        $this->sidLength         = strlen($sid);
        $this->sessionNameLength = strlen(session_name());

        return true;
    }

    /**
     * Read session data
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.read.php
     *
     * @param string $sid The session id to read data for.
     *
     * @return string <p>
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function read($sid)
    {
        if ($this->isOpened === false) {
            $this->open(self::SESSION_PATH, self::SESSION_NAME);
        }
        if (isset($_COOKIE[$sid]) === false) {
            return '';
        }
        $this->decryptString($_COOKIE[$sid], $this->secret, $sid);

        return $this->value;
    }

    /**
     * Write session data
     *
     * @link  http://php.net/manual/en/sessionhandlerinterface.write.php
     *
     * @param string $sid          The session id.
     * @param string $sessionData  <p>
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
     * @throws CookieSizeException
     * @throws OpenSSLException
     * @since 5.4.0
     */
    public function write($sid, $sessionData)
    {
        if ($this->isOpened === false) {
            $this->open(self::SESSION_PATH, self::SESSION_NAME);
        }
        $encryptedString = $this->encryptString($sessionData, $this->secret);

        $digest = hash_hmac($this->digestAlgo, $sid . $encryptedString, $this->secret, true);
        $output = base64_encode($digest . $encryptedString);

        if ((strlen($output) + $this->sessionNameLength +
             strlen($sid) + self::MIN_LEN_PER_COOKIE) > self::COOKIE_SIZE
        ) {
            throw new CookieSizeException(
                'The cookie size in '
                . self::COOKIE_SIZE . ' was exceeded.'
            );
        }

        $isSet = setcookie(
            $sid,
            $output,
            ($this->cookieParams["lifetime"] > 0) ? time() + $this->cookieParams["lifetime"] : 0,
            $this->cookieParams["path"],
            $this->cookieParams["domain"],
            $this->cookieParams["secure"],
            $this->cookieParams["httponly"]
        );
        // ensure session is closed after data has been written
        session_write_close();

        return $isSet;
    }

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
     * @param  string $in  String to encrypt.
     * @param  string $key Encryption key.
     *
     * @return string The encrypted string.
     * @throws \Exception
     */
    public function encryptString(string $in, string $key)
    {
        // Build an initialisation vector
        $iv = random_bytes($this->cipherIvLen);
        // Hash the key
        $keyHash   = openssl_digest($key, $this->digestAlgo, true);
        $encrypted = openssl_encrypt($in, $this->cipherAlgo, $keyHash, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new OpenSSLException('encryptString() - Encryption failed: ' . openssl_error_string());
        }
        // The result comprises the IV and encrypted data
        $res = pack(self::PACK_CODE, time() + $this->cookieExpTime) . $iv . $encrypted;

        return base64_encode($res);
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
                'decryptString() - data length ' . strlen($raw) . ' is less than iv length ' . $this->cipherKeylen
            );
        }

        $digest = substr($raw, 0, $this->digestLength);
        if ($digest === false) {
            return '';
        }
        $message = substr($raw, $this->digestLength);
        if ($message === false) {
            return '';
        }

        if ($this->hashesEqual($digest, $message, $sid) === false) {
            return '';
        }

        $validTill = substr($message, 0, self::META_DATA_SIZE);
        $exp       = unpack(self::PACK_CODE, $validTill)[1];
        if (time() > $exp) {
            return '';
        }

        // 2nd base64_decode for message pack(self::PACK_CODE, time() + $this->cookieExpTime) . $iv . $encrypted
        $message = base64_decode($message);
        // Extract the initialisation vector and encrypted data
        $iv  = substr($message, 0, $this->cipherIvLen);
        $raw = substr($message, $this->cipherIvLen);
        // Hash the key
        $keyHash = openssl_digest($key, $this->digestAlgo, true);
        $res     = openssl_decrypt($raw, $this->digestAlgo, $keyHash, OPENSSL_RAW_DATA, $iv);
        if ($res === false) {
            throw new OpenSSLException('decryptString - decryption failed: ' . openssl_error_string());
        }

        return $res;
    }
}