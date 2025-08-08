<?php

use Akrez\HttpProxy\RequestFactory;
use Akrez\HttpProxy\Senders\PureSender;
use GuzzleHttp\Psr7\ServerRequest;

require_once '../vendor/autoload.php';

$serverRequest = ServerRequest::fromGlobals();
$requestFactory = RequestFactory::fromServerRequest($serverRequest);
if ($requestFactory) {
    (new PureSender)->emit($requestFactory->getNewServerRequest());
}
