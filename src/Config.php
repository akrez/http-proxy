<?php

namespace Akrez\HttpProxy;

class Config
{
    protected ?string $method = null;

    protected ?string $scheme = null;

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

    public function setMethod(?string $method): self
    {
        $this->method = $method;

        return $this;
    }

    public function setScheme(?string $scheme): self
    {
        $this->scheme = $scheme;

        return $this;
    }

    public function setDebug(bool $debug): self
    {
        $this->debug = $debug;

        return $this;
    }

    public function setBase64(bool $base64): self
    {
        $this->base64 = $base64;

        return $this;
    }

    public function setTimeout(int $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    public function setByConfigString(string $configString)
    {
        $configs = $this->sanitizeConfig($configString);

        return $this
            ->setMethod($configs['method'])
            ->setScheme($configs['scheme'])
            ->setDebug($configs['debug'])
            ->setBase64($configs['base64'])
            ->setTimeout($configs['timeout']);
    }

    protected function sanitizeConfig(string $configString): array
    {
        $configs = explode('_', strtolower($configString));

        return [
            'method' => $this->findInArray($configs, ['get', 'post', 'head', 'put', 'delete', 'options', 'trace', 'connect', 'patch']),
            'scheme' => $this->findInArray($configs, ['https', 'http']),
            'debug' => $this->findInArray($configs, ['debug']) === 'debug',
            'base64' => $this->findInArray($configs, ['base64']) === 'base64',
            'timeout' => 60,
        ];
    }

    protected function findInArray(array $needles, array $haystack, ?string $default = null): ?string
    {
        foreach ($needles as $needle) {
            if (in_array($needle, $haystack)) {
                return $needle;
            }
        }

        return $default;
    }
}
