<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

class Envelope
{
    protected ?RequestInterface $request = null;

    public function request(): ?RequestInterface
    {
        return $this->request;
    }

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

    public function send()
    {
        if (! $this->request) {
            $response = new Response(500);
        }

        header('Content-Type: application/octet-stream', true, 200);

        if ($this->config->debug()) {
            $response = new Response(200, [], nl2br(Message::toString($this->request)));
        } elseif ($this->request->getMethod() === 'CONNECT') {
            $response = new Response(200, [], '');
        } else {
            $options = [
                'http_errors' => false,
                'allow_redirects' => false,
                'verify' => false,
                'timeout' => $this->config->timeout(),
                'connect_timeout' => $this->config->timeout(),
            ];
            $client = new Client;
            $response = $client->send($this->request, $options)
                ->withoutHeader('Transfer-Encoding');
        }

        $raw = Message::toString($response);
        echo $raw;
        flush();
    }

    public static function emit(?ServerRequestInterface $serverRequest = null)
    {
        if (! $serverRequest) {
            $serverRequest = ServerRequest::fromGlobals();
        }

        $config = Config::make($serverRequest);
        if (! $config) {
            return false;
        }

        $envelope = new Envelope($serverRequest, $config);
        if (! $envelope->request()) {
            return false;
        }

        $envelope->send();

        return true;
    }
}
