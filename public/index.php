<?php

require_once '../vendor/autoload.php';

use Akrez\HttpProxy\Factories\InbodyFactory;
use Akrez\HttpProxy\Factories\InlineFactory;
use Akrez\HttpProxy\Senders\CurlSender;
use Akrez\HttpProxy\Senders\EnvelopeSender;

function inline()
{
    return InlineFactory::emitSender(new CurlSender);
}

function inbody()
{
    return InbodyFactory::emitSender(new CurlSender);
}

function envelope()
{
    return InbodyFactory::emitSender(new EnvelopeSender);
}
