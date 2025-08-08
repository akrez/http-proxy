<?php

namespace Akrez\HttpProxy\Senders;

use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\ServerRequestInterface;

class DebugSender
{
    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        echo nl2br(Message::toString($newServerRequest));
    }
}
