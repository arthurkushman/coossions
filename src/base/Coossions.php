<?php
namespace coossions\base;

use coossions\crypt\Encryptor;
use coossions\exceptions\AlgoNotFoundException;
use coossions\exceptions\CookieSizeException;
use coossions\exceptions\OpenSSLException;

class Coossions extends Encryptor implements BaseInterface
{
    private $sidLength         = 0;
    private $sessionNameLength = 0;
    private $cookieParams      = [];

    private $isOpened = false;

    /**
     * Coossions constructor.
     * @param string $secret the secret key to be used in openssl_digest
     */
    public function __construct(string $secret)
    {
        parent::__construct($secret);
        $this->expire        = $this->getExpire();
        $this->digestAlgo    = $this->getDigestAlgo();
        $this->cipherAlgo    = $this->getCipherAlgo();
        $this->cipherIvLen   = openssl_cipher_iv_length($this->cipherAlgo);
    }

    /**
     * Setter for DI via Encryptor ex. if user wants to override params
     *
     * @param Encryptor $encryptor
     * @throws AlgoNotFoundException
     */
    public function setEncryption(Encryptor $encryptor)
    {
        $this->expire = $encryptor->getExpire();
        $this->digestAlgo    = $encryptor->getDigestAlgo();
        $this->cipherAlgo    = $encryptor->getCipherAlgo();
        // check if there are cipher and digest algos exist
        $cipherMethods = openssl_get_cipher_methods();
        $digestMethods = openssl_get_md_methods();
        if (in_array($this->digestAlgo, $digestMethods) === false)
        {
            throw new AlgoNotFoundException('Digest algorithm ' . $this->digestAlgo . ' not found');
        }
        if (in_array($this->cipherAlgo, $cipherMethods) === true)
        {
            throw new AlgoNotFoundException('Cipher algorithm ' . $this->cipherAlgo . ' not found');
        }
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
    public function close(): bool
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
    public function destroy($sid): bool
    {
        setcookie($sid, '', time() - 3600); // erase cookie in path that they were set in
        setcookie($sid, '', time() - 3600, '/'); // erase cookie for current domain

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
    public function gc($maxlifetime): bool
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
    public function open($savePath, $sid): bool
    {
        $this->cookieParams      = session_get_cookie_params();
        $this->digestLength      = strlen(hash($this->digestAlgo, '', true));
        $this->cipherIvLen       = openssl_cipher_iv_length($this->cipherAlgo);
        $this->sidLength         = strlen($sid);
        $this->sessionNameLength = strlen(session_name());

        return $this->isOpened = true;
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
    public function read($sid): string
    {
        if ($this->isOpened === false) {
            $this->open(self::SESSION_PATH, self::SESSION_NAME);
        }
        if (isset($_COOKIE[$sid]) === false) {
            return '';
        }

        return $this->decryptString($_COOKIE[$sid], $this->secret, $sid);
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
    public function write($sid, $sessionData): bool
    {
        if ($this->isOpened === false) {
            $this->open(self::SESSION_PATH, self::SESSION_NAME);
        }
        $output = $this->encryptString($sessionData, $this->secret, $sid);

        if ((strlen($output) + $this->sessionNameLength +
                $this->sidLength + self::MIN_LEN_PER_COOKIE) > self::COOKIE_SIZE
        ) {
            throw new CookieSizeException(
                'The cookie size of '
                . self::COOKIE_SIZE . ' bytes was exceeded.'
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

        return $isSet;
    }
}