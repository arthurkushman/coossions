<?php
namespace coossionstest;

use PHPUnit\Framework\TestCase;
use coossions\crypt\Encryptor;

/**
 * Class EncryptorTest
 * @package coossionstest
 *
 * @property Encryptor encryptor
 */
final class EncryptorTest extends TestCase
{
    private $encryptor = null;
    private $sid = 'sid';
    private $secret = 'secret';

    public function setUp()
    {
        $this->encryptor = new Encryptor('secret');
        $this->sid = md5($this->sid);
    }

    public function testEncryption()
    {
        $msg = 'foo bar baz';
        $encryptedStr = $this->encryptor->encryptString($msg, $this->secret, $this->sid);
        $this->assertEquals($this->encryptor->decryptString($encryptedStr, $this->secret, $this->sid), $msg);
    }

    public function testSetGetDigestAlgo()
    {
        $sha128 = 'sha128';
        $this->encryptor->setDigestAlgo($sha128);
        $this->assertEquals($sha128, $this->encryptor->getDigestAlgo());
    }

    public function testSetGetCipherAlgo()
    {
        $aes128 = 'aes-128-ctr';
        $this->encryptor->setCipherAlgo($aes128);
        $this->assertEquals($aes128, $this->encryptor->getCipherAlgo());
    }

    public function testSetGetCipherIvLen()
    {
        $ivLen32 = 32;
        $this->encryptor->setCipherIvLen($ivLen32);
        $this->assertEquals($ivLen32, $this->encryptor->getCipherIvLen());
    }

    public function testSetGetExpires()
    {
        $expire = 360;
        $this->encryptor->setExpire($expire);
        $this->assertEquals($expire, $this->encryptor->getExpire());
    }
}