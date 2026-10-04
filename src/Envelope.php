<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

class Envelope
{
    protected ?RequestInterface $request = null;

    public function __construct(
        protected RequestInterface $serverRequest,
        protected Config $config
    ) {
        try {
            $scheme = $config->scheme() ?: $serverRequest->getUri()->getScheme();
            //
            $request = Message::parseRequest((string) $serverRequest->getBody());
            $uri = $request->getUri()->withScheme($scheme);
            $this->request = $request->withUri($uri);
        } catch (Exception $e) {
            $this->request = null;
        }
    }

    public function emit()
    {
        if ($this->config->debug()) {
            $response = new Response(200, [], nl2br(Message::toString($this->request)));
        } elseif ($this->request->getMethod() === 'CONNECT') {
            $response = new Response(200, [], '');
        } else {
            $options = [
                'http_errors' => false,
                'allow_redirects' => false,
                'verify' => false,
                'decode_content' => false,
                'timeout' => $this->config->timeout(),
                'connect_timeout' => $this->config->timeout(),
                'curl' => [
                    CURLOPT_HTTP_TRANSFER_DECODING => false,
                    CURLOPT_HTTP_CONTENT_DECODING => false,
                    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                ],
            ];
            $client = new Client;
            $response = $client->send($this->request, $options);
        }

        $raw = Message::toString($response);
        header('Content-Type: application/octet-stream', true, 200);
        echo $raw;
        flush();
    }
}
