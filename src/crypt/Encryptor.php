<?php

namespace coossions\crypt;

class Encryptor
{
    protected $expire       = 2592000; // 30 days
    protected $digestAlgo   = 'sha256';
    protected $cipherAlgo   = 'aes-256-ctr';
    protected $cipherIvLen  = 64; // sha256 length
    protected $digestLength = 0;
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