<?php

namespace Akrez\HttpProxy\Factories;

use Akrez\HttpProxy\Factory;
use Exception;
use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\RequestInterface;

class InbodyFactory extends Factory
{
    public function make(): ?RequestInterface
    {
        try {
            $newServerRequest = Message::parseRequest((string) $this->globalServerRequest);

            $uri = $newServerRequest->getUri();
            $uri = $uri->withScheme($this->scheme);
            $newServerRequest = $newServerRequest->withUri($uri);

            return $newServerRequest;
        } catch (Exception $e) {
            return null;
        }
    }
}
