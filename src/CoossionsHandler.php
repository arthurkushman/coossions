<?php
/**
 * Created by PhpStorm.
 * User: arthur
 * Date: 05.04.17
 * Time: 20:10
 */

namespace coossions;

use coossions\base\Coossions;
use coossions\base\CoossionsContractInterface;

class CoossionsHandler extends Coossions implements CoossionsContractInterface
{

    /**
     * Starts session with SessionHandlerInterface impl + cookie encryption
     *
     * @param bool $start if true session starts manually, set to false if php.ini session.autostart = 1
     */
    public function startSession(bool $start = true)
    {
        session_set_save_handler($this);
        session_register_shutdown();
        if(true === $start) {
            session_start();
        }
    }
}