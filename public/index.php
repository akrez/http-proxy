<?php

require_once '../vendor/autoload.php';

use Akrez\HttpProxy\Inline;
use Akrez\HttpProxy\Factories\InbodyFactory;
use Akrez\HttpProxy\Senders\CurlSender;
use Akrez\HttpProxy\Senders\EnvelopeSender;

function inline()
{
    return Inline::emit();
}

function inbody()
{
    return InbodyFactory::emitSender(new CurlSender);
}

function envelope()
{
    return InbodyFactory::emitSender(new EnvelopeSender);
}
