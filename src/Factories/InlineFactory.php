<?php

namespace Akrez\HttpProxy\Factories;

use Akrez\HttpProxy\Factory;
use GuzzleHttp\Psr7\MultipartStream;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

class InlineFactory extends Factory
{
    public function make(): ?RequestInterface
    {
        if (empty($this->hostPath)) {
            return null;
        }

        if ($this->base64()) {
            $this->hostPath = base64_decode($this->hostPath, true);
        }

        $newUri = $this->createUri($this->globalServerRequest, $this->scheme, $this->hostPath);

        $newServerRequest = clone $this->globalServerRequest;

        $newServerRequest = $newServerRequest->withUri($newUri);
        if ($this->method) {
            $newServerRequest = $newServerRequest->withMethod($this->method);
        }

        $multipartBoundary = $this->getMultipartBoundary($this->globalServerRequest);
        if ($multipartBoundary) {
            $newServerRequest = $newServerRequest->withBody(
                $this->getMultipartStream($multipartBoundary, $this->globalServerRequest)
            );
        }

        return $newServerRequest;
    }

    private function createUri(ServerRequestInterface $serverRequest, string $scheme, string $hostPath)
    {
        $uri = new Uri($scheme.'://'.$hostPath);
        $uri = $uri->withQuery($serverRequest->getUri()->getQuery());
        $uri = $uri->withFragment($serverRequest->getUri()->getFragment());

        return $uri;
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
