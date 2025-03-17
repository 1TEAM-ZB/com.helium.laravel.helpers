<?php

namespace Helium\LaravelHelpers\Helpers\Tests;

use Http\Client\Curl\Client;
use Nyholm\Psr7\Factory\HttplugFactory;
use rpkamp\Mailhog\MailhogClient;

class Mailhog
{
    protected static $client;

    public static function client(): MailhogClient
    {
        if (!self::$client) {
            $host = config('mail.mailhog.host', 'mailhog');
            $port = config('mail.mailhog.port', '8025');
            $uri = "http://{$host}:{$port}";

            self::$client =  new MailhogClient(
                new Client(),
                new HttplugFactory(),
                $uri
            );
        }

        return self::$client;
    }
}