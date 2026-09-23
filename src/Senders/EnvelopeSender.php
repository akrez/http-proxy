<?php

namespace Akrez\HttpProxy\Senders;

use Akrez\HttpProxy\Sender;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\RequestInterface;

class EnvelopeSender extends Sender
{
    protected function emitRequest(RequestInterface $newRequest)
    {
        $options = [
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => false,
            'decode_content' => false,
            'curl' => [
                CURLOPT_HTTP_TRANSFER_DECODING => false,
                CURLOPT_HTTP_CONTENT_DECODING => false,
            ],
        ];

        if ($this->timeout !== null) {
            $options['timeout'] = $this->timeout;
            $options['connect_timeout'] = $this->timeout;
        }

        $client = new Client;
        $response = $client->send($newRequest, $options);

        $raw = Message::toString($response);

        header('Content-Type: application/octet-stream', true, 200);
        echo $raw;
        flush();
    }
}
