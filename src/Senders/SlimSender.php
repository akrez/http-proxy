<?php

namespace Akrez\HttpProxy\Senders;

use Akrez\HttpProxy\Emitters\SlimEmitter;
use Exception;
use GuzzleHttp\Client;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

class SlimSender
{
    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        if ($newServerRequest->hasHeader('Accept-Encoding')) {
            $newServerRequest = $newServerRequest
                ->withoutHeader('Accept-Encoding')
                ->withHeader('Accept-Encoding', 'identity');
        }
        $newServerRequest = $newServerRequest->withoutHeader('referer');

        $clientConfig = [
            'verify' => false,
            'allow_redirects' => false,
            'referer' => false,
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
            (new SlimEmitter)->emit($response);
        } catch (Throwable $e) {
            return $e;
        } catch (Exception $e) {
            return $e;
        }

        return null;
    }
}
