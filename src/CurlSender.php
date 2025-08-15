<?php

namespace Akrez\HttpProxy;

use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\RequestInterface;

class CurlSender
{
    protected ?int $timeout = null;

    protected int $bufferSize = 128;

    protected bool $debug = false;

    public function setTimeout(?int $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    public function setBufferSize(?int $bufferSize): self
    {
        $this->bufferSize = $bufferSize;

        return $this;
    }

    public function setDebug(bool $debug): self
    {
        $this->debug = $debug;

        return $this;
    }

    public function emit(RequestInterface $newRequest)
    {
        $newRequest = $newRequest
            ->withoutHeader('Accept-Encoding')
            ->withHeader('Accept-Encoding', 'identity');

        if ($this->debug) {
            echo nl2br(Message::toString($newRequest));
        } elseif ($newRequest->getMethod() === 'CONNECT') {
            header('Content-Type: application/json; charset=utf-8', true, 200);
            echo json_encode([
                'status' => 200,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        } else {
            $this->emitRequest($newRequest);
        }
    }

    protected function emitRequest(RequestInterface $newRequest)
    {
        $url = (string) $newRequest->getUri();

        $headers = [];
        foreach ($newRequest->getHeaders() as $name => $values) {
            $headers[] = $name.': '.implode(', ', $values);
        }

        $options = [
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT => $this->timeout,

            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,

            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,

            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_AUTOREFERER => false,

            CURLOPT_HEADERFUNCTION => [$this, 'headerCallback'],
            CURLOPT_WRITEFUNCTION => [$this, 'writeCallback'],

            CURLOPT_FORBID_REUSE => true,
            CURLOPT_FRESH_CONNECT => true,

            CURLOPT_BUFFERSIZE => $this->bufferSize,

            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $newRequest->getMethod(),
            CURLOPT_POSTFIELDS => (string) $newRequest->getBody(),
            CURLOPT_HTTPHEADER => $headers,

            CURLOPT_HTTP_CONTENT_DECODING => false,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, $options);
        curl_exec($ch);
        curl_close($ch);

        return true;
    }

    private function headerCallback($ch, $headers)
    {
        $parts = explode(':', $headers, 2);

        if (count($parts) == 2) {
            if (in_array(strtolower($parts[0]), [
                // 'content-length',
                // 'content-encoding',
                // 'transfer-encoding',
                // 'keep-alive',
                // 'connection',
            ])) {
                // do nothing
            } else {
                header($headers, false);
            }
        } elseif (preg_match('/HTTP\/[\d.]+\s*(\d+)/', $headers, $matches)) {
            http_response_code($matches[1]);
        } else {
            // do nothing
        }

        return strlen($headers);
    }

    private function writeCallback($ch, $str)
    {
        $len = strlen($str);

        echo $str;
        flush();

        return $len;
    }
}
