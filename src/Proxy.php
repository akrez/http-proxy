<?php

namespace Akrez\HttpProxy;

use Psr\Http\Message\ServerRequestInterface;

class Proxy
{
    public static function inlineGuzzleSapi(ServerRequestInterface $serverRequest)
    {
        $inlineinitiator = new InlineInitiator($serverRequest);
        $guzzleSender = new GuzzleSender;
        $sapiEmitter = new SapiEmitter;

        $canInitiate = $inlineinitiator->initiate();
        if (! $canInitiate) {
            return false;
        }

        $request = $inlineinitiator->request();

        $response = $guzzleSender->send($request, $inlineinitiator->config());

        $sapiEmitter->emit($response);

        return true;
    }

    public static function inlineCurl(ServerRequestInterface $serverRequest)
    {
        $inlineinitiator = new InlineInitiator($serverRequest);
        $curlStreamer = new CurlStreamer;

        $canInitiate = $inlineinitiator->initiate();
        if (! $canInitiate) {
            return false;
        }

        $request = $inlineinitiator->request();

        $curlStreamer->send($request, $inlineinitiator->config());

        return true;
    }

    public static function inlineGuzzle(ServerRequestInterface $serverRequest)
    {
        $inlineinitiator = new InlineInitiator($serverRequest);
        $curlStreamer = new GuzzleStreamer('php://output', 'wb');

        $canInitiate = $inlineinitiator->initiate();
        if (! $canInitiate) {
            return false;
        }

        $request = $inlineinitiator->request();

        $curlStreamer->send($request, $inlineinitiator->config());

        return true;
    }
}
