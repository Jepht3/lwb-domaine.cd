<?php
/**
 * LWB Domaine .cd — requête WHOIS en TCP (port 43).
 *
 * @license MIT
 */

namespace LwbDomaineCd;

final class WhoisClient
{
    /** Taille maximale lue (les réponses du registre font quelques Ko). */
    private const MAX_BYTES = 65536;

    /** @var string */
    private $host;

    /** @var int */
    private $port;

    /** @var float */
    private $timeout;

    /** @var callable|null */
    private $connector;

    /**
     * @param callable|null $connector fonction (host, port, timeout) => ressource de flux ; pour les tests
     */
    public function __construct(string $host = 'whois.nic.cd', int $port = 43, float $timeout = 5.0, ?callable $connector = null)
    {
        $this->host = $host;
        $this->port = $port;
        $this->timeout = $timeout > 0 ? $timeout : 5.0;
        $this->connector = $connector;
    }

    /**
     * Interroge le serveur WHOIS et renvoie la réponse brute.
     *
     * @throws WhoisException connexion impossible, délai dépassé ou erreur de lecture
     */
    public function query(string $domain): string
    {
        $stream = $this->connect();
        try {
            stream_set_timeout($stream, (int) floor($this->timeout), (int) (($this->timeout - floor($this->timeout)) * 1000000));
            if (@fwrite($stream, $domain . "\r\n") === false) {
                throw new WhoisException('écriture impossible vers ' . $this->host);
            }
            $response = '';
            while (!feof($stream) && strlen($response) < self::MAX_BYTES) {
                $chunk = fread($stream, 8192);
                $meta = stream_get_meta_data($stream);
                if (!empty($meta['timed_out'])) {
                    throw new WhoisException('délai dépassé (' . $this->timeout . ' s) en attendant ' . $this->host);
                }
                if ($chunk === false) {
                    throw new WhoisException('lecture impossible depuis ' . $this->host);
                }
                if ($chunk === '' && feof($stream)) {
                    break;
                }
                $response .= $chunk;
            }
            return $response;
        } finally {
            fclose($stream);
        }
    }

    /**
     * @return resource
     */
    private function connect()
    {
        if ($this->connector !== null) {
            $stream = call_user_func($this->connector, $this->host, $this->port, $this->timeout);
            if (!is_resource($stream)) {
                throw new WhoisException('connexion impossible à ' . $this->host . ':' . $this->port);
            }
            return $stream;
        }
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client('tcp://' . $this->host . ':' . $this->port, $errno, $errstr, $this->timeout);
        if (!is_resource($stream)) {
            throw new WhoisException('connexion impossible à ' . $this->host . ':' . $this->port . ' (' . ($errstr !== '' ? $errstr : 'erreur ' . $errno) . ')');
        }
        return $stream;
    }
}
