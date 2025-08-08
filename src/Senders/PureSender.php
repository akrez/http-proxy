<?php

namespace Akrez\HttpProxy\Senders;

use GuzzleHttp\Client;
use Psr\Http\Message\ServerRequestInterface;

class PureSender
{
    public $bufferSize = 128;

    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        $newServerRequest = $newServerRequest
            ->withoutHeader('Accept-Encoding')
            ->withHeader('Accept-Encoding', 'identity');

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

        $response = $client->send($newServerRequest);

        http_response_code($response->getStatusCode());
        foreach ($response->getHeaders() as $headerKey => $headers) {
            header($headerKey.': '.implode(', ', $headers), false);
        }

        $body = $response->getBody();
        while (! $body->eof()) {
            echo $body->read($this->bufferSize);
            flush();
        }
    }
}
