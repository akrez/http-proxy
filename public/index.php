<?php

require_once '../vendor/autoload.php';

use Akrez\HttpProxy\Factories\InbodyFactory;
use Akrez\HttpProxy\Factories\InlineFactory;
use Akrez\HttpProxy\Senders\CurlSender;

function inline()
{
    return InlineFactory::emitSender(new CurlSender);
}

function inbody()
{
    return InbodyFactory::emitSender(new CurlSender);
}
