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
        if ($request->hasHeader('Accept-Encoding')) {
            $request = $request->withoutHeader('Accept-Encoding');
        }

        $response = $this->guzzleSender->send($request, $this->inlineinitiator->config());

        $this->sapiEmitter->emit($response);

        return true;
    }
}
