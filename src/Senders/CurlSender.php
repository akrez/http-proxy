<?php

namespace Akrez\HttpProxy\Senders;

use Psr\Http\Message\ServerRequestInterface;

class CurlSender
{
    public $bufferSize = 128;

    public function emit(ServerRequestInterface $newServerRequest, $timeout = null)
    {
        $newServerRequest = $newServerRequest
            ->withoutHeader('Accept-Encoding')
            ->withHeader('Accept-Encoding', 'identity');

        $url = (string) $newServerRequest->getUri();

        $headers = [];
        foreach ($newServerRequest->getHeaders() as $name => $values) {
            $headers[] = $name.': '.implode(', ', $values);
        }

        $protocolVersion = match ($newServerRequest->getProtocolVersion()) {
            '1.0' => CURL_HTTP_VERSION_1_0,
            '1.1' => CURL_HTTP_VERSION_1_1,
            '2' => CURL_HTTP_VERSION_2,
            '2.0' => CURL_HTTP_VERSION_2_0,
            '2.0-tls' => CURL_HTTP_VERSION_2TLS,
            '2.0-prio' => CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
            default => CURL_HTTP_VERSION_NONE,
        };

        $options = [
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,

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
            CURLOPT_CUSTOMREQUEST => $newServerRequest->getMethod(),
            CURLOPT_POSTFIELDS => (string) $newServerRequest->getBody(),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HTTP_VERSION => $protocolVersion,

            CURLOPT_HTTP_CONTENT_DECODING => false,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, $options);
        curl_exec($ch);
        curl_close($ch);

        return true;
    }

    protected function headerCallback($ch, $headers)
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

    protected function writeCallback($ch, $str)
    {
        $len = strlen($str);

        echo $str;
        flush();

        return $len;
    }
}
