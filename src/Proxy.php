<?php

namespace Akrez\HttpProxy;

use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

class Proxy
{
    public function __construct(
        protected InlineInitiator $inlineinitiator,
        protected GuzzleSender $guzzleSender,
        protected SapiEmitter $sapiEmitter,
    ) {}

    public function resolve(): bool
    {
        $canInitiate = $this->inlineinitiator->initiate();
        if (! $canInitiate) {
            return false;
        }

        $this->disableHostCompress();

        $response = $this->guzzleSender->send(
            $this->inlineinitiator->request(),
            $this->inlineinitiator->config(),
        );

        $this->sapiEmitter->emit($response);

        return true;
    }

    public static function resolveSapiInlineGuzzle(?ServerRequestInterface $serverRequest = null)
    {
        if (! $serverRequest) {
            $serverRequest = ServerRequest::fromGlobals();
        }

        return (new self(
            new InlineInitiator($serverRequest),
            new GuzzleSender,
            new SapiEmitter,
        ))->resolve();
    }

    protected function disableHostCompress(): void
    {
        // Disable PHP's built-in gzip output compression
        ini_set('zlib.output_compression', '0');

        // Clean any active output buffers (e.g. ob_gzhandler)
        while (ob_get_level()) {
            ob_end_clean();
        }

        // Disable Apache mod_deflate compression
        if (function_exists('apache_setenv')) {
            apache_setenv('no-gzip', '1');
        }

        // Prevent Nginx from buffering/compressing the proxied response
        if (! headers_sent()) {
            header('X-Accel-Buffering: no');
        }
    }
}
