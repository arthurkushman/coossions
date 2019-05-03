<?php

namespace coossions\exceptions;

class AlgoNotFoundException extends \Exception
{
    public function __construct($message)
    {
        parent::__construct($message);
    }
}