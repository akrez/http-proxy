<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\MultipartStream;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class Inline
{
    protected ?RequestInterface $request = null;

    public function request(): ?RequestInterface
    {
        return $this->request;
    }

    public function __construct(
        protected ServerRequestInterface $serverRequest,
        protected Config $config
    ) {
        try {
            $hostPath = $config->hostPath();
            if (empty($hostPath)) {
                throw new Exception;
            }

            $scheme = $config->scheme() ?: $serverRequest->getUri()->getScheme();

            if ($config->base64()) {
                $newUri = new Uri($scheme.'://'.base64_decode($hostPath));
            } else {
                $newUri = new Uri($scheme.'://'.$hostPath);
                $newUri = $newUri->withQuery($serverRequest->getUri()->getQuery());
                $newUri = $newUri->withFragment($serverRequest->getUri()->getFragment());
            }

            $newRequest = clone $serverRequest;
            $newRequest = $newRequest->withUri($newUri);
            if ($config->method()) {
                $newRequest = $newRequest->withMethod($config->method());
            }

            $multipartBoundary = $this->getMultipartBoundary($serverRequest);
            if ($multipartBoundary) {
                $newRequest = $newRequest->withBody(
                    $this->getMultipartStream($multipartBoundary, $serverRequest)
                );
            }

            $this->request = $newRequest;
        } catch (Exception $e) {
            $this->request = null;
        }
    }

    public function send()
    {
        if (! $this->request) {
            $response = new Response(500);
        }

        if ($this->request->hasHeader('Accept-Encoding')) {
            $this->request = $this->request
                ->withoutHeader('Accept-Encoding')
                ->withHeader('Accept-Encoding', 'identity');
        }

        $streamer = new SimpleStreamer('php://output', 'w+');

        if ($this->config->debug()) {
            $response = new Response(200, [], nl2br(Message::toString($this->request)));
            echo $response->getBody()->__toString();
        } elseif ($this->request->getMethod() === 'CONNECT') {
            $response = new Response(200, [], '');
            echo $response->getBody()->__toString();
        } else {
            $options = [
                'referer' => false,
                'http_errors' => false,
                'allow_redirects' => false,
                'verify' => false,
                'timeout' => $this->config->timeout(),
                'connect_timeout' => $this->config->timeout(),
                'decode_content' => false,
                //
                'sink' => $streamer,
                'on_headers' => fn (ResponseInterface $response) => $streamer->onHeaders($response),
            ];
            $client = new Client;
            $response = $client->send($this->request, $options);
        }
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

        $inline = new Inline($serverRequest, $config);
        if (! $inline->request()) {
            return false;
        }

        $inline->send();

        return true;
    }

    private function getMultipartBoundary(ServerRequestInterface $globalServerRequest): ?string
    {
        $contentType = $globalServerRequest->getHeaderLine('Content-Type');

        if (
            strpos($contentType, 'multipart/form-data') === 0 and
            preg_match('/boundary=(.*)$/', $contentType, $matches)
        ) {
            return trim($matches[1], '"');
        }

        return null;
    }

    private function getMultipartStream(string $multipartBoundary, ServerRequestInterface $globalServerRequest)
    {
        $elements = [];

        foreach ($globalServerRequest->getParsedBody() as $key => $value) {
            $elements[] = [
                'name' => $key,
                'contents' => $value,
            ];
        }

        foreach ($globalServerRequest->getUploadedFiles() as $key => $value) {
            if (empty($value->getError())) {
                $elements[] = [
                    'name' => $key,
                    'filename' => $value->getClientFilename(),
                    'contents' => $value->getStream(),
                ];
            }
        }

        return new MultipartStream($elements, $multipartBoundary);
    }
}
