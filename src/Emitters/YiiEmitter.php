<?php

declare(strict_types=1);

namespace Akrez\HttpProxy\Emitters;

use Psr\Http\Message\ResponseInterface;

use function flush;
use function headers_sent;
use function in_array;
use function sprintf;

/**
 * `SapiEmitter` sends a response using standard PHP Server API i.e. with {@see header()} and "echo".
 *
 * @internal
 */
class YiiEmitter
{
    private const NO_BODY_RESPONSE_CODES = [
        'CONTINUE' => 100,
        'SWITCHING_PROTOCOLS' => 101,
        'PROCESSING' => 102,
        'NO_CONTENT' => 204,
        'RESET_CONTENT' => 205,
        'NOT_MODIFIED' => 304,
    ];

    private const DEFAULT_BUFFER_SIZE = 8_388_608; // 8MB

    private int $bufferSize;

    /**
     * @param  int|null  $bufferSize  The size of the buffer in bytes to send the content of the message body.
     */
    public function __construct(?int $bufferSize = null)
    {
        if ($bufferSize !== null && $bufferSize < 1) {
            throw new \Exception('Buffer size must be greater than zero.');
        }

        $this->bufferSize = $bufferSize ?? self::DEFAULT_BUFFER_SIZE;
    }

    /**
     * Responds to the client with headers and body.
     *
     * @param  ResponseInterface  $response  Response object to send.
     * @param  bool  $withoutBody  If body should be ignored.
     *
     * @throws Exception
     */
    public function emit(ResponseInterface $response, bool $withoutBody = false): void
    {
        $level = ob_get_level();
        $status = $response->getStatusCode();
        $withoutBody = $withoutBody || ! $this->shouldOutputBody($response);
        $withoutContentLength = $withoutBody || $response->hasHeader('Transfer-Encoding');

        if ($withoutContentLength) {
            $response = $response->withoutHeader('Content-Length');
        }

        // We can't send headers if they are already sent.
        if (headers_sent()) {
            throw new \Exception('headers have been sent.');
        }

        header_remove();

        // Send headers.
        foreach ($response->getHeaders() as $header => $values) {
            foreach ($values as $value) {
                header("$header: $value", false);
            }
        }

        // Send HTTP Status-Line (must be sent after the headers).
        header(sprintf(
            'HTTP/%s %d %s',
            $response->getProtocolVersion(),
            $status,
            $response->getReasonPhrase(),
        ), true, $status);

        if ($withoutBody) {
            return;
        }

        // Adds a `Content-Length` header if a body exists, and it has not been added before.
        if (! $withoutContentLength && ! $response->hasHeader('Content-Length')) {
            $contentLength = $response
                ->getBody()
                ->getSize();

            if ($contentLength !== null) {
                header("Content-Length: $contentLength", true);
            }
        }

        /**
         * Sends headers before the body.
         * Makes a client possible to recognize the type of the body content if it is sent with a delay,
         * for instance, for a streamed response.
         */
        flush();

        $this->emitBody($response, $level);
    }

    private function emitBody(ResponseInterface $response, int $level): void
    {
        $body = $response->getBody();

        if ($body->isSeekable()) {
            $body->rewind();
        }

        $size = $body->getSize();
        if ($size !== null && $size <= $this->bufferSize) {
            $this->emitContent($body->getContents(), $level);

            return;
        }

        while (! $body->eof()) {
            $this->emitContent($body->read($this->bufferSize), $level);
        }
    }

    private function emitContent(string $content, int $level): void
    {
        if ($content === '') {
            while (ob_get_level() > $level) {
                ob_end_flush();
            }

            return;
        }

        echo $content;

        // flush the output buffer and send echoed messages to the browser
        while (ob_get_level() > $level) {
            ob_end_flush();
        }
        flush();
    }

    private function shouldOutputBody(ResponseInterface $response): bool
    {
        if (in_array($response->getStatusCode(), self::NO_BODY_RESPONSE_CODES, true)) {
            return false;
        }

        $body = $response->getBody();

        if (! $body->isReadable()) {
            return false;
        }

        $size = $body->getSize();

        if ($size !== null) {
            return $size > 0;
        }

        if ($body->isSeekable()) {
            $body->rewind();
            $byte = $body->read(1);

            if ($byte === '' || $body->eof()) {
                return false;
            }
        }

        return true;
    }
}
