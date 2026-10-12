<?php

namespace LwbDomaineCd\Tests;

use LwbDomaineCd\ResponseParser;
use LwbDomaineCd\WhoisClient;
use LwbDomaineCd\WhoisException;
use PHPUnit\Framework\TestCase;

final class WhoisClientTest extends TestCase
{
    /** Flux en mémoire qui contient déjà la « réponse » du serveur. */
    private static function memoryConnector(string $response): callable
    {
        return function () use ($response) {
            $stream = fopen('php://memory', 'w+');
            fwrite($stream, $response);
            rewind($stream);
            return $stream;
        };
    }

    public function testReturnsRawResponse(): void
    {
        $raw = (string) file_get_contents(__DIR__ . '/fixtures/taken-ispbunia-ac-cd.txt');
        $client = new WhoisClient('whois.nic.cd', 43, 2.0, self::memoryConnector($raw));
        $this->assertStringContainsString('Registry Domain ID: 33365-niccd', $client->query('ispbunia.ac.cd'));
    }

    public function testEmptyResponseGivesUnknownStatus(): void
    {
        $client = new WhoisClient('whois.nic.cd', 43, 2.0, self::memoryConnector(''));
        $raw = $client->query('abc.cd');
        $this->assertSame('', $raw);
        $this->assertSame(ResponseParser::UNKNOWN, (new ResponseParser())->parse('abc.cd', $raw)['status']);
    }

    public function testTimeoutThrows(): void
    {
        // Serveur local qui accepte la connexion mais ne répond jamais.
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $this->assertIsResource($server);
        $port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

        $client = new WhoisClient('127.0.0.1', $port, 0.5);
        $start = microtime(true);
        try {
            $client->query('abc.cd');
            $this->fail('Une exception était attendue.');
        } catch (WhoisException $e) {
            $this->assertStringContainsString('délai', $e->getMessage());
            $this->assertLessThan(3.0, microtime(true) - $start);
        } finally {
            fclose($server);
        }
    }

    public function testConnectionRefusedThrows(): void
    {
        // Port libéré juste avant : la connexion est refusée.
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
        fclose($server);

        $this->expectException(WhoisException::class);
        (new WhoisClient('127.0.0.1', $port, 1.0))->query('abc.cd');
    }

    public function testConnectorFailureThrows(): void
    {
        $this->expectException(WhoisException::class);
        (new WhoisClient('whois.nic.cd', 43, 1.0, function () {
            return false;
        }))->query('abc.cd');
    }
}
