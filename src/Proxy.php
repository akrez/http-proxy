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

        $request = $this->inlineinitiator->request();
        $request = $this->filterAcceptEncoding($request);

        $response = $this->guzzleSender->send($request, $this->inlineinitiator->config());

        $this->sapiEmitter->emit($response);

        return true;
    }

    private function filterAcceptEncoding($request)
    {
        if (! $request->hasHeader('Accept-Encoding')) {
            return $request;
        }

        $supported = $this->getSupportedEncodings();

        $clientEncodings = array_map('trim', explode(',', $request->getHeaderLine('Accept-Encoding')));

        $filtered = [];
        foreach ($clientEncodings as $encoding) {
            // Extract encoding name without quality value (e.g. "gzip;q=0.8" -> "gzip")
            $name = strtolower(trim(explode(';', $encoding)[0]));
            if (in_array($name, $supported, true)) {
                $filtered[] = $encoding;
            }
        }

        if (empty($filtered)) {
            $filtered[] = 'identity';
        }

        return $request
            ->withoutHeader('Accept-Encoding')
            ->withHeader('Accept-Encoding', implode(', ', $filtered));
    }

    private function getSupportedEncodings(): array
    {
        $encodings = ['identity'];

        if (function_exists('gzdecode')) {
            $encodings[] = 'gzip';
        }

        if (function_exists('gzinflate')) {
            $encodings[] = 'deflate';
        }

        if (function_exists('brotli_uncompress')) {
            $encodings[] = 'br';
        }

        if (function_exists('zstd_uncompress')) {
            $encodings[] = 'zstd';
        }

        return $encodings;
    }
}
