<?php

namespace Akrez\HttpProxy;

use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\RequestInterface;

class CurlStreamer
{
    public function send(RequestInterface $request, Config $config)
    {
        if ($request->getMethod() === 'CONNECT') {
            return;
        }

        if ($config->debug()) {
            echo nl2br(Message::toString($request));

            return;
        }

        $url = (string) $request->getUri();

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[] = $name.': '.implode('; ', $values);
        }

        $options = [
            CURLOPT_CONNECTTIMEOUT => $config->timeout(),
            CURLOPT_TIMEOUT => $config->timeout(),

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

            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $request->getMethod(),
            CURLOPT_POSTFIELDS => (string) $request->getBody(),
            CURLOPT_HTTPHEADER => $headers,

            CURLOPT_HTTP_CONTENT_DECODING => false,
            CURLOPT_HTTP_VERSION => $this->getProtocolVersion($request),
        ];

        $ch = curl_init();
        curl_setopt_array($ch, $options);
        curl_exec($ch);
    }

    protected function headerCallback($ch, $headers)
    {
        $parts = explode(':', $headers, 2);

        if (count($parts) == 2) {
            if (in_array(strtolower($parts[0]), [
                // 'proxy-authenticate',
                // 'proxy-authorization',
                // 'te',
                // 'transfer-encoding',
                // 'keep-alive',
                // 'connection',
                // 'trailer',
                // 'upgrade',
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

    protected function getProtocolVersion(RequestInterface $request): int
    {
        $protocolVersion = $request->getProtocolVersion();

        if (in_array($protocolVersion, ['1.0'])) {
            return CURL_HTTP_VERSION_1_0;
        }
        if (in_array($protocolVersion, ['1.1'])) {
            return CURL_HTTP_VERSION_1_1;
        }
        if (in_array($protocolVersion, ['2', '2.0'])) {
            if (defined('CURL_HTTP_VERSION_2TLS')) {
                return CURL_HTTP_VERSION_2TLS;
            }
            if (defined('CURL_HTTP_VERSION_2_0')) {
                return CURL_HTTP_VERSION_2_0;
            }
        }
        if (in_array($protocolVersion, ['3', '3.0'])) {
            if (defined('CURL_HTTP_VERSION_3')) {
                return CURL_HTTP_VERSION_3;
            }
        }

        return CURL_HTTP_VERSION_NONE;
    }
}
