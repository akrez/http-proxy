<?php

namespace Akrez\HttpProxy;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class GuzzleStreamer implements StreamInterface
{
    use StreamDecoratorTrait;

    private string $filename;

    private string $mode;

    private ?StreamInterface $stream;

    public function __construct(string $filename, string $mode)
    {
        $this->filename = $filename;
        $this->mode = $mode;

        // unsetting the property forces the first access to go through
        // __get().
        unset($this->stream);
    }

    public function send(RequestInterface $request, Config $config)
    {
        if ($request->getMethod() === 'CONNECT') {
            return;
        }

        if ($config->debug()) {
            echo nl2br(Message::toString($request));

            return;
        }

        $options = [
            'referer' => false,
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => false,
            'timeout' => $config->timeout(),
            'connect_timeout' => $config->timeout(),
            'decode_content' => false,
            // 'stream' => true,
            //
            'sink' => $this,
            'on_headers' => fn (ResponseInterface $response) => $this->onHeaders($response),
        ];
        $client = new Client;
        $client->send($request, $options);
    }

    protected function createStream(): StreamInterface
    {
        return Utils::streamFor(Utils::tryFopen($this->filename, $this->mode));
    }

    protected function onHeaders(ResponseInterface $response): void
    {
        // We can't send headers if they are already sent
        if (headers_sent()) {
            throw new Exception('headers have been sent.');
        }

        header_remove();

        $skipHeaders = [
        ];

        $headers = $response->getHeaders();

        // Send headers
        foreach ($headers as $header => $values) {
            if (! in_array(strtolower($header), $skipHeaders)) {
                foreach ($values as $value) {
                    header("$header: $value", false);
                }
            }
        }

        // Send HTTP Status-Line (must be sent after the headers)
        $status = $response->getStatusCode();
        header(
            sprintf(
                'HTTP/%s %d %s',
                $response->getProtocolVersion(),
                $status,
                $response->getReasonPhrase(),
            ),
            true,
            $status
        );

        flush();
    }
}
