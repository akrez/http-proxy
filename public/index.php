<?php

use Akrez\HttpProxy\GuzzleSender;
use Akrez\HttpProxy\InlineInitiator;
use Akrez\HttpProxy\Proxy;
use Akrez\HttpProxy\SapiEmitter;
use GuzzleHttp\Psr7\ServerRequest;

include '../vendor/autoload.php';

function resolveSapiInlineGuzzle()
{
    $serverRequest = ServerRequest::fromGlobals();

    return (new Proxy(
        new InlineInitiator($serverRequest),
        new GuzzleSender,
        new SapiEmitter,
    ))->resolve();
}
