<?php

namespace Akrez\HttpProxy;

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

        $response = $this->guzzleSender->send(
            $this->inlineinitiator->request(),
            $this->inlineinitiator->config(),
        );

        $this->sapiEmitter->emit($response);

        return true;
    }
}
