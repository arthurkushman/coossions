<?php
namespace coossions\base;


interface CoossionsContractInterface
{
    /**
     * Starts session with SessionHandlerInterface impl + cookie encryption
     *
     * @param bool $start if true session starts manually, set to false if php.ini session.autostart = 1
     */
    public function startSession(bool $start = true);
}