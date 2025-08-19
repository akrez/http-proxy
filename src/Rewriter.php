<?php

namespace Akrez\HttpProxy;

use Akrez\HttpProxy\Senders\RewriteSender;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

abstract class Rewriter
{
    public function __construct(protected RewriteSender $rewriteSender) {}

    abstract public function convert($content, $mainPageUrl);

    abstract public function isMine(RequestInterface $newRequest, ResponseInterface $response);

    public function encryptUrl(string $urlString, ?string $mainUrlString = null)
    {
        return $this->rewriteSender->encryptUrl($urlString, $mainUrlString);
    }

    protected static function isContentType(string $contentType, ResponseInterface $response)
    {
        $contentTypes = (array) $response->getHeader('Content-Type');

        return $contentType === trim(preg_replace('@;.*@', '', reset($contentTypes)));
    }

    protected static function startsWith($haystack, $needles)
    {
        foreach ((array) $needles as $needle) {
            if ($needle !== '' && stripos($haystack, $needle) === 0) {
                return true;
            }
        }

        return false;
    }
}
