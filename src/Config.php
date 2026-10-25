<?php

namespace Akrez\HttpProxy;

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

    public function setHostPath(?string $hostPath): self
    {
        $this->hostPath = $hostPath;

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
}
