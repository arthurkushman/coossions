<?php

namespace coossions\exceptions;

class OpenSSLException extends \Exception
{
    public function __construct($message)
    {
        parent::__construct($message);
    }
}