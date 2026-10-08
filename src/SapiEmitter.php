<?php

declare(strict_types=1);

namespace Akrez\HttpProxy;

use Psr\Http\Message\ResponseInterface;

use function flush;
use function header;
use function header_remove;
use function headers_sent;
use function sprintf;

/**
 * `SapiEmitter` sends a response using standard PHP Server API, i.e., with {@see header()} and "echo".
 */
final class SapiEmitter
{
    private const DEFAULT_BUFFER_SIZE = 1_048_576; // 1MB

    /**
     * @psalm-var positive-int
     */
    private int $bufferSize;

    private array $skipHeaders = [];

    public function setSkipHeaders(array $headers): self
    {
        $this->skipHeaders = $headers;

        return $this;
    }

    public function getSkipHeaders(): array
    {
        return $this->skipHeaders;
    }

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

    public function emit(ResponseInterface $response, bool $withoutBody = false): void
    {
        $this->emitHeaders($response);

        /**
         * Sends headers before the body.
         * Makes a client possible to recognize the type of the body content if it is sent with a delay,
         * for instance, for a streamed response.
         */
        flush();

        if (! $withoutBody) {
            $this->emitBody($response);
        }
    }

    /**
     * @throws HeadersHaveBeenSentException If headers have already been sent.
     */
    private function emitHeaders(ResponseInterface $response): void
    {
        // We can't send headers if they are already sent
        if (headers_sent()) {
            throw new \Exception('headers have been sent.');
        }

        header_remove();

        $headers = $response->getHeaders();

        // Send headers
        foreach ($headers as $header => $values) {
            if (! in_array(strtolower($header), $this->skipHeaders)) {
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
    }

    private function emitBody(ResponseInterface $response): void
    {
        $level = ob_get_level();
        $body = $response->getBody();
        if (! $body->isReadable()) {
            return;
        }

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
}
