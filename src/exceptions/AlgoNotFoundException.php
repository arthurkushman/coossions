<?php

namespace coossions\exceptions;

class AlgoNotFoundException extends \Exception
{
    public function __construct($message, $code, \Exception $previous)
    {
        parent::__construct($message, $code, $previous);
    }
}