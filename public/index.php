<?php

use Akrez\HttpProxy\Proxy;
use GuzzleHttp\Psr7\ServerRequest;

include '../vendor/autoload.php';

$serverRequest = ServerRequest::fromGlobals();

Proxy::inlineGuzzleSapi($serverRequest);
