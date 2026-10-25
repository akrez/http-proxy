<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\MultipartStream;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

class InlineInitiator
{
    protected ?Config $config = null;

    public function config(): ?Config
    {
        return $this->config;
    }

    protected ?RequestInterface $request = null;

    public function request(): ?RequestInterface
    {
        return $this->request;
    }

    public function __construct(
        protected ServerRequestInterface $serverRequest,
    ) {}

    public function initiate(): bool
    {
        try {
            $this->request = null;
            $this->config = null;

            $serverRequest = $this->serverRequest;

            $configStringHostPath = $this->extractConfigStringHostPath($serverRequest);
            if ($configStringHostPath === null) {
                return false;
            }

            [
                0 => $configString,
                1 => $hostPath,
            ] = explode('/', $configStringHostPath, 2) + [0 => '', 1 => ''];
            if (empty($hostPath)) {
                return false;
            }

            $config = (new Config)->setByConfigString($configString);

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
            $this->config = $config;

            return true;

        } catch (Exception $e) {
        }

        return false;
    }

    protected function extractConfigStringHostPath(ServerRequestInterface $globalServerRequest): ?string
    {
        [
            'REQUEST_URI' => $requestUri,
            'SCRIPT_NAME' => $scriptName,
        ] = $globalServerRequest->getServerParams() + ['SCRIPT_NAME' => null, 'REQUEST_URI' => null];

        if (
            is_string($requestUri) && is_string($scriptName) &&
            ($requestUri !== '') && ($scriptName !== '') &&
            (strpos($requestUri, $scriptName) === 0)
        ) {
            $url = substr($requestUri, strlen($scriptName));

            return ltrim($url, " \n\r\t\v\0/");
        }

        return null;
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
