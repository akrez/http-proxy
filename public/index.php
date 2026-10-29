<?php

include '../vendor/autoload.php';

use Akrez\HttpProxy\Proxy;
use GuzzleHttp\Psr7\ServerRequest;

Proxy::inlineCurl(ServerRequest::fromGlobals());
