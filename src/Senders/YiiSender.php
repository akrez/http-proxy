<?php

namespace Akrez\HttpProxy\Senders;

use Akrez\HttpProxy\Emitters\YiiEmitter;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;

class YiiSender
{
    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        if ($newServerRequest->hasHeader('Accept-Encoding')) {
            $newServerRequest = $newServerRequest
                ->withoutHeader('Accept-Encoding')
                ->withHeader('Accept-Encoding', 'gzip');
        }
        $newServerRequest = $newServerRequest->withoutHeader('referer');

        $clientConfig = [
            'verify' => false,
            'allow_redirects' => false,
            'referer' => false,
            'decode_content' => false,
            'http_errors' => false,
        ];
        if ($timeout !== null) {
            $clientConfig += [
                'timeout' => $timeout,
                'connect_timeout' => $timeout,
                'read_timeout' => $timeout,
            ];
        }

        $client = new Client($clientConfig);

        try {
            $response = $client->send($newServerRequest);
            $response = $response
                // ->withoutHeader('Content-Length')
                ->withoutHeader('Connection')
                ->withoutHeader('Content-Encoding')
                ->withoutHeader('Keep-Alive')
                ->withoutHeader('Transfer-Encoding');
        } catch (Exception $e) {
            $response = new Response(500, ['Content-Type' => 'application/json; charset=utf-8'], json_encode([
                'host' => gethostname(),
                'message' => $e->getMessage(),
            ]));
        }

        (new YiiEmitter)->emit($response);
    }
}
