<?php

namespace Akrez\HttpProxy;

class Proxy
{
    public function __construct(
        protected InlineInitiator $inlineinitiator,
        protected GuzzleSender $guzzleSender,
        protected SapiEmitter $sapiEmitter,
    ) {}

    public function resolve()
    {
        $canInitiate = $this->inlineinitiator->initiate();
        if ($canInitiate) {
            $response = $this->guzzleSender->stream(
                $this->inlineinitiator->request(),
                $this->inlineinitiator->config(),
            );
            $this->sapiEmitter->emit($response);
        }
    }
}
