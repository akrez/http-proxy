<?php

namespace Akrez\HttpProxy\Senders;

use Akrez\HttpProxy\Rewriters\TextCssRewriter;
use Akrez\HttpProxy\Rewriters\TextHtmlRewriter;
use Akrez\HttpProxy\Support\RewriteCookie;
use Akrez\HttpProxy\Support\RewriteCrypt;
use Akrez\HttpRunner\SapiEmitter;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Throwable;

class RewriteSender implements StreamInterface
{
    use StreamDecoratorTrait;

    protected $rewriters = [];

    protected ?ResponseInterface $response = null;

    private ?ServerRequestInterface $newServerRequest;

    private ?StreamInterface $stream;

    public function __construct(
        public RewriteCrypt $rewriteCrypt,
        public RewriteCookie $rewriteCookie,
        private string $filename,
        private string $mode
    ) {
        unset($this->stream);
    }

    protected function createStream()
    {
        return Utils::streamFor(Utils::tryFopen($this->filename, $this->mode));
    }

    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        ini_set('output_buffering', 'Off');
        ini_set('output_handler', '');
        ini_set('zlib.output_compression', 0);

        $this->newServerRequest = $this->rewriteCookie->onBeforeRequest($newServerRequest);

        $clientConfig = [
            'verify' => false,
            'allow_redirects' => false,
            'referer' => false,
            // 'decode_content' => false,
            'http_errors' => false,
            'sink' => $this,
            'on_headers' => fn (ResponseInterface $response) => $this->onHeaders($response),
        ];
        if ($timeout) {
            $clientConfig += [
                'timeout' => $timeout,
                'connect_timeout' => $timeout,
                'read_timeout' => $timeout,
            ];
        }

        try {
            $client = new Client($clientConfig);
            $client->send($newServerRequest);
            if ($this->rewriters) {
                return $this->emitRewritedResponse();
            }
        } catch (Throwable $e) {
            return $e;
        } catch (Exception $e) {
            return $e;
        }

        return null;
    }

    public function onHeaders(ResponseInterface $response)
    {
        $this->response = $response;

        $this->rewriters = $this->detectRewriters($response);

        $this->response = $this->rewriteCookie->onHeadersReceived($this->newServerRequest, $this->response);

        $locationHeaders = $response->getHeader('location');
        if ($locationHeaders) {
            $this->response = $this->response->withoutHeader('location');
            foreach ($locationHeaders as $locationHeader) {
                $newLocation = $this->rewriteCrypt->encryptUrl($locationHeader, $this->newServerRequest->getUri()->__toString());
                $this->response = $this->response->withAddedHeader('location', $newLocation);
            }
        }

        if ($this->rewriters) {
            $this->filename = tempnam(sys_get_temp_dir(), 'rewrite_streamer_');
            $this->response = $this->response
                ->withoutHeader('Content-Length')
                ->withoutHeader('Transfer-Encoding');
        } else {
            $this->filename = 'php://output';
            (new SapiEmitter)->emit((clone $this->response)
                ->withoutHeader('Content-Length')
                ->withoutHeader('Transfer-Encoding'), true);
        }
    }

    protected function emitRewritedResponse()
    {
        $contents = file_get_contents($this->filename);
        @unlink($this->filename);

        $this->response = $this->response->withoutHeader('content-length');
        $this->response = $this->response->withoutHeader('transfer-encoding');

        foreach ($this->rewriters as $rewriter) {
            $contents = $rewriter->convert($contents, $this->newServerRequest->getUri()->__toString());
        }

        $response = $this->cloneResponse($this->response, $contents);

        (new SapiEmitter)->emit($response);
    }

    protected function detectRewriters(ResponseInterface $response)
    {
        $rewriters = [];
        foreach ([
            TextHtmlRewriter::class,
            TextCssRewriter::class,
        ] as $rewriterClass) {
            $rewriter = new $rewriterClass($this);
            if ($rewriter->isMine($response)) {
                $rewriters[] = $rewriter;
            }
        }

        return $rewriters;
    }

    public function cloneResponse($response, $body)
    {
        return new Response(
            $response->getStatusCode(),
            $response->getHeaders(),
            $body,
            $response->getProtocolVersion(),
            $response->getReasonPhrase()
        );
    }
}
