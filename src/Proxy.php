<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\MultipartStream;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

class Proxy
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
                $decodedHostPath = base64_decode(rawurldecode($hostPath), true);
                $newUri = new Uri($scheme.'://'.$decodedHostPath);
            } else {
                $newUri = new Uri($scheme.'://'.$hostPath);
                $newUri = $newUri->withQuery($serverRequest->getUri()->getQuery());
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

    public function send(): bool
    {
        if (! $this->request) {
            return false;
        }

        if ($this->request->hasHeader('Accept-Encoding')) {
            $this->request = $this->request
                ->withoutHeader('Accept-Encoding')
                ->withHeader('Accept-Encoding', 'identity');
        }

        if ($this->config->debug()) {
            echo nl2br(Message::toString($this->request));
        } elseif ($this->request->getMethod() === 'CONNECT') {
        } else {
            $streamer = new GuzzleStreamer('php://output', 'wb');
            // $streamer = new CurlStreamer;
            $streamer->stream($this->request, $this->config);
        }

        return true;
    }

    public static function emit(?ServerRequestInterface $serverRequest = null): bool
    {
        if (! $serverRequest) {
            $serverRequest = ServerRequest::fromGlobals();
        }

        $config = Config::make($serverRequest);
        if (! $config) {
            return false;
        }

        $proxy = new static($serverRequest, $config);
        if (! $proxy->request()) {
            return false;
        }

        return $proxy->send();
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
