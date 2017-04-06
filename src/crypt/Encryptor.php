<?php

namespace coossions\crypt;

class Encryptor
{
    private $expire = 2592000; // 30 days
    private $digestAlgo = 'sha256';
    private $cipherAlgo = 'aes-256-ctr';
    private $cipherKeylen = 32;

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
     * @param int $cipherKeylen
     */
    public function setCipherKeylen($cipherKeylen)
    {
        $this->cipherKeylen = $cipherKeylen;
    }

    /**
     * @return int
     */
    public function getCipherKeylen()
    {
        return $this->cipherKeylen;
    }

}