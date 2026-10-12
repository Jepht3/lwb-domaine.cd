<?php
/**
 * LWB Domaine .cd — analyse d'une réponse WHOIS du registre .cd (CoCCA).
 *
 * Règle d'or : un domaine n'est « disponible » que si le registre le dit
 * explicitement. Tout ce qui n'est pas reconnu avec certitude donne « unknown ».
 *
 * @license MIT
 */

namespace LwbDomaineCd;

final class ResponseParser
{
    public const AVAILABLE = 'available';
    public const REGISTERED = 'registered';
    public const RESERVED = 'reserved';
    public const UNKNOWN = 'unknown';

    /**
     * Phrases « libre » par défaut. La première est celle relevée sur
     * whois.nic.cd le 12/10/2026 : « Domain Status: No Object Found ».
     */
    public const DEFAULT_FREE_PHRASES = [
        'No Object Found',
        'No match',
        'No Data Found',
        'not found',
        'is available',
    ];

    /** Phrases qui signalent un nom réservé par le registre (jamais vendable). */
    public const DEFAULT_RESERVED_PHRASES = [
        'Registrar: NIC Reserved',
    ];

    /** Messages de refus ou de limite de requêtes : le statut reste inconnu. */
    private const ERROR_PATTERN = '/(rate limit|limit exceeded|query limit|too many (requests|queries)|try again later|access denied|blocked)/i';

    /** @var string[] */
    private $freePhrases;

    /** @var string[] */
    private $reservedPhrases;

    /**
     * @param string[] $freePhrases     phrases qui prouvent que le domaine n'existe pas
     * @param string[] $reservedPhrases phrases qui prouvent que le nom est réservé
     */
    public function __construct(array $freePhrases = self::DEFAULT_FREE_PHRASES, array $reservedPhrases = self::DEFAULT_RESERVED_PHRASES)
    {
        $this->freePhrases = self::clean($freePhrases);
        $this->reservedPhrases = self::clean($reservedPhrases);
    }

    /**
     * Construit la liste à partir d'un champ texte de configuration (une phrase par ligne).
     *
     * @return string[]
     */
    public static function phrasesFromText(string $text, array $default): array
    {
        $lines = self::clean(preg_split('/\R/', $text) ?: []);
        return $lines ?: $default;
    }

    /**
     * @return array{status: string, reason: string}
     */
    public function parse(string $domain, string $raw): array
    {
        $domain = strtolower(trim($domain));
        $record = self::record($raw);
        if ($record === '') {
            return self::result(self::UNKNOWN, 'réponse vide');
        }

        $nameLine = null;
        if (preg_match('/^\s*Domain Name:\s*(\S+)\s*$/mi', $record, $m)) {
            $nameLine = strtolower(rtrim($m[1], '.'));
        }
        if ($nameLine !== null && $nameLine !== $domain) {
            return self::result(self::UNKNOWN, 'la réponse concerne un autre domaine (' . $nameLine . ')');
        }
        if ($nameLine === null && preg_match(self::ERROR_PATTERN, $record)) {
            return self::result(self::UNKNOWN, 'refus ou limite de requêtes du registre');
        }

        foreach ($this->reservedPhrases as $phrase) {
            if (self::contains($record, $phrase)) {
                return self::result(self::RESERVED, 'réservé par le registre (' . $phrase . ')');
            }
        }
        if (preg_match('/^\s*Domain Status:\s*(inactive|serverHold)\b/mi', $record, $m)) {
            return self::result(self::RESERVED, 'statut registre ' . $m[1]);
        }
        if (preg_match('/^\s*(Registry Domain ID|Creation Date):/mi', $record, $m)) {
            return self::result(self::REGISTERED, 'enregistré (' . $m[1] . ')');
        }
        // La réponse « libre » de whois.nic.cd contient aussi « Domain Name: … » :
        // la phrase de non-existence doit être testée avant cette ligne.
        foreach ($this->freePhrases as $phrase) {
            if (self::contains($record, $phrase)) {
                return self::result(self::AVAILABLE, 'libre (' . $phrase . ')');
            }
        }
        if ($nameLine === $domain) {
            return self::result(self::REGISTERED, 'enregistré (Domain Name)');
        }

        return self::result(self::UNKNOWN, 'réponse non reconnue');
    }

    /** Partie utile de la réponse : avant « >>> Last update » et les conditions d'utilisation. */
    private static function record(string $raw): string
    {
        $raw = str_replace("\r", '', $raw);
        foreach (['>>> Last update', 'TERMS OF USE'] as $marker) {
            $pos = stripos($raw, $marker);
            if ($pos !== false) {
                $raw = substr($raw, 0, $pos);
            }
        }
        return trim($raw);
    }

    private static function contains(string $haystack, string $phrase): bool
    {
        $pattern = '/' . str_replace('\ ', '\s+', preg_quote($phrase, '/')) . '/i';
        return (bool) preg_match($pattern, $haystack);
    }

    /**
     * @param array<int, mixed> $phrases
     * @return string[]
     */
    private static function clean(array $phrases): array
    {
        $out = [];
        foreach ($phrases as $phrase) {
            $phrase = trim((string) $phrase);
            if ($phrase !== '') {
                $out[] = $phrase;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * @return array{status: string, reason: string}
     */
    private static function result(string $status, string $reason): array
    {
        return ['status' => $status, 'reason' => $reason];
    }
}
