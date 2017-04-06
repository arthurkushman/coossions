<?php
/**
 * Created by ArthurKushman.
 * Date: 05.04.17
 * Time: 20:17
 */

namespace coossions\base;

use SessionHandlerInterface;

interface BaseInterface extends SessionHandlerInterface
{
    function encryptString(string $in, string $key);
    function decryptString(string $in, string $key);
}