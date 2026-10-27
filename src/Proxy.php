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

        $response = $this->guzzleSender->send($request, $this->inlineinitiator->config());

        $this->sapiEmitter->setSkipHeaders([
            'proxy-authenticate',
            'proxy-authorization',
            'te',
            'transfer-encoding',
            'keep-alive',
            'connection',
            'trailer',
            'upgrade',
        ])->emit($response);

        return true;
    }

}
