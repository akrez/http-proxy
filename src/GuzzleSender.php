<?php

namespace Akrez\HttpProxy;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class GuzzleSender
{
    public function send(RequestInterface $request, Config $config): ResponseInterface
    {
        if ($request->getMethod() === 'CONNECT') {
            return new Response;
        }

        if ($config->debug()) {
            return new Response(200, [], nl2br(Message::toString($request)));
        }

        $options = [
            'referer' => false,
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => false,
            'timeout' => $config->timeout(),
            'connect_timeout' => $config->timeout(),
            // 'decode_content' => false,
        ];

        $client = new Client;

        return $client->send($request, $options);
    }
}
