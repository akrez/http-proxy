<?php

namespace Akrez\HttpProxy;

use Akrez\HttpRunner\SapiEmitter;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class Agent
{
    protected RequestInterface $request;

    protected bool $debug;

    public function __construct(RequestInterface $request, $debug = false)
    {
        $this->request = $request;
        $this->debug = boolval($debug);
    }

    public function emit($timeout = 60, $clientConfig = [])
    {
        ini_set('output_buffering', 'Off');
        ini_set('output_handler', '');
        ini_set('zlib.output_compression', 0);

        $response = $this->sendRequest($this->request, $timeout, $clientConfig, $this->debug);
        if ($response) {
            (new SapiEmitter)->emit($response);
        }
    }

    protected function sendRequest(RequestInterface $request, $timeout, $clientConfig, $debug): ?Response
    {
        if ($debug) {
            return new Response(200, [], Message::toString($request));
        }

        $client = new Client(array_replace_recursive([
            'timeout' => $timeout,
            'connect_timeout' => $timeout,
            'read_timeout' => $timeout,
            'verify' => false,
            'allow_redirects' => false,
            'referer' => false,
            'sink' => fopen('php://output', 'w'),
            'on_headers' => function (ResponseInterface $response) {
                (new SapiEmitter)->emit($response, true);
            },
            'decode_content' => false,
        ], $clientConfig));

        try {
            $client->send($request);

            return null;
        } catch (ClientException $e) {
            return $e->getResponse();
        } catch (ServerException $e) {
            return $e->getResponse();
        } catch (Throwable $e) {
            return new Response(500, [], json_encode((array) $e), 1.1, 'Internal Server Throwable Error');
        } catch (Exception $e) {
            return new Response(500, [], json_encode((array) $e), 1.1, 'Internal Server Exception Error');
        }
    }
}
