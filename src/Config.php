<?php

namespace Akrez\HttpProxy;

use Exception;
use Psr\Http\Message\ServerRequestInterface;

class Config
{
    protected ?string $method = null;

    protected ?string $scheme = null;

    protected ?string $hostPath = null;

    protected bool $debug = false;

    protected bool $base64 = false;

    protected int $timeout = 60;

    public function method(): ?string
    {
        return $this->method;
    }

    public function scheme(): ?string
    {
        return $this->scheme;
    }

    public function hostPath(): ?string
    {
        return $this->hostPath;
    }

    public function debug(): bool
    {
        return $this->debug;
    }

    public function base64(): bool
    {
        return $this->base64;
    }

    public function timeout(): int
    {
        return $this->timeout;
    }

    public function __construct(
        ServerRequestInterface $globalServerRequest,
        int $timeout = 60
    ) {
        $configStringHostPath = $this->extractConfigStringHostPath($globalServerRequest);
        if ($configStringHostPath === null) {
            throw new Exception;
        }

        [
            0 => $configString,
            1 => $hostPath,
        ] = explode('/', $configStringHostPath, 2) + [0 => '', 1 => ''];

        $configs = $this->sanitizeConfig($configString);

        $this->method = $configs['method'];
        $this->scheme = $configs['scheme'];
        $this->hostPath = $hostPath;
        $this->debug = $configs['debug'];
        $this->base64 = $configs['base64'];
        $this->timeout = $timeout;
    }

    public static function make(ServerRequestInterface $globalServerRequest): ?self
    {
        try {
            return new self($globalServerRequest);
        } catch (Exception $e) {
            return null;
        }
    }

    protected function extractConfigStringHostPath(ServerRequestInterface $globalServerRequest): ?string
    {
        [
            'REQUEST_URI' => $requestUri,
            'SCRIPT_NAME' => $scriptName,
        ] = $globalServerRequest->getServerParams() + ['SCRIPT_NAME' => null, 'REQUEST_URI' => null];

        if (
            strpos($requestUri, $scriptName) === 0 and
            strlen($scriptName) <= strlen($requestUri)
        ) {
            $url = substr($requestUri, strlen($scriptName));

            return ltrim($url, " \n\r\t\v\0/");
        }

        return null;
    }

    protected function sanitizeConfig(string $configString): array
    {
        $configs = explode('_', $configString);

        return [
            'method' => $this->findInArray($configs, ['get', 'post', 'head', 'put', 'delete', 'options', 'trace', 'connect', 'patch']),
            'scheme' => $this->findInArray($configs, ['https', 'http']),
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
}
