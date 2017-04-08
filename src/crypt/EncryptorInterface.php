<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 08.04.17
 * Time: 11:32
 */

namespace coossions\crypt;


interface EncryptorInterface
{
    const MIN_LEN_PER_COOKIE = 6;
    const COOKIE_SIZE        = 4096;
    const PACK_CODE          = 'V';
    const META_DATA_SIZE     = 4;
}