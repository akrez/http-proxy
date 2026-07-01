<?php

namespace Akrez\HttpProxy;

use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class Factory
{
    protected ?string $method = null;

    protected ?string $scheme = null;

    protected ?string $hostPath = null;

    protected bool $debug = false;

    protected bool $base64 = false;

    public function __construct(protected ServerRequestInterface $globalServerRequest)
    {
        [
            'SCRIPT_NAME' => $scriptName,
            'REQUEST_URI' => $requestUri,
        ] = $globalServerRequest->getServerParams() + ['SCRIPT_NAME' => null, 'REQUEST_URI' => null];

        if (
            strpos($requestUri, $scriptName) === 0 and
            strlen($scriptName) <= strlen($requestUri)
        ) {
            $url = substr($requestUri, strlen($scriptName));
            $url = ltrim($url, " \n\r\t\v\0/");
        } else {
            return null;
        }

        [
            0 => $configString,
            1 => $this->hostPath,
        ] = explode('/', $url, 2) + [0 => null, 1 => null];

        [
            'method' => $this->method,
            'scheme' => $this->scheme,
            'debug' => $this->debug,
            'base64' => $this->base64,
        ] = $this->sanitizeConfig($globalServerRequest, explode('_', $configString));
    }

    public function debug(): bool
    {
        return $this->debug;
    }

    public function base64(): bool
    {
        return $this->base64;
    }

    protected function sanitizeConfig(ServerRequestInterface $globalServerRequest, array $configs): array
    {
        return [
            'method' => $this->findInArray($configs, ['get', 'post', 'head', 'put', 'delete', 'options', 'trace', 'connect', 'patch'], $globalServerRequest->getMethod()),
            'scheme' => $this->findInArray($configs, ['https', 'http'], $globalServerRequest->getUri()->getScheme()),
            'debug' => $this->findInArray($configs, ['debug']) === 'debug',
            'base64' => $this->findInArray($configs, ['base64']) === 'base64',
        ];
    }

    protected function findInArray(array $needles, array $haystack, ?string $default = null): ?string
    {
        foreach ($needles as $needle) {
            if (in_array(strtolower($needle), $haystack)) {
                return $needle;
            }
        }

        return $default;
    }

    public static function emitSender(Sender $sender, $factory = null): ?RequestInterface
    {
        if($factory === null) {
            $serverRequest = ServerRequest::fromGlobals();
            $factory = new static($serverRequest);
        }
        $newRequest = $factory->make();
        if ($newRequest) {
            $sender->setDebug($factory->debug())->emit($newRequest);
        }

        return $newRequest;
    }

    abstract public function make(): ?RequestInterface;
}
