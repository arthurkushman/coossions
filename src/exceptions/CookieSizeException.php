<?php

namespace coossions\exceptions;

class CookieSizeException extends \Exception
{
    public function __construct($message)
    {
        parent::__construct($message);
    }
}