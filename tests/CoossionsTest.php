<?php
namespace coossionstest;

use coossions\base\Coossions;
use coossions\CoossionsHandler;
use coossions\crypt\Encryptor;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptorTest
 * @package coossionstest
 *
 * @property Coossions coossions
 * @property Encryptor encryptor
 */
final class CoossionsTest extends TestCase
{
    private $coossions = null;
    private $sid = 'sid';
    private $secret = 'secret';

    public function setUp()
    {
        $this->coossions = new Coossions($this->secret);
        $this->encryptor = new Encryptor($this->secret);
        $this->sid = md5($this->sid);
    }

    public function testSetEncryption()
    {
        $sha512 = 'sha512';
        $aes128 = 'aes-256-cbc';
        $this->encryptor->setDigestAlgo($sha512); // defaults to sha256
        $this->encryptor->setCipherAlgo($aes128); // defaults to aes-256-ctr
        $this->coossions->setEncryption($this->encryptor);
        $this->assertEquals($this->coossions->getDigestAlgo(), $sha512);
        $this->assertEquals($this->coossions->getCipherAlgo(), $aes128);
    }

    /**
     * We must run this test in separate process coz of setcookie headers
     * @runInSeparateProcess
     */
    public function testSessionHandlerMethods()
    {
        $data = 'foo bar baz';
        $this->assertTrue($this->coossions->open('', $this->sid));
        $this->assertTrue($this->coossions->write($this->sid, $data));
        $this->assertEquals('', $this->coossions->read($this->sid));
        $this->assertTrue($this->coossions->close());
        $this->assertTrue($this->coossions->destroy($this->sid));
        $this->assertTrue($this->coossions->gc(1000));
    }

//    public function testCoossionsHandler()
//    {
//        $coossions = new CoossionsHandler($this->secret); // any secret word
//        $coossions->startSession();
//        // testing that session_starts normally and have defined an empty global array
//        $this->assertArraySubset([], $_SESSION);
//    }

//    public function testExceptions()
//    {
//
//    }
}