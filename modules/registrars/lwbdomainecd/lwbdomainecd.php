<?php
/**
 * LWB Domaine .cd — vérification de disponibilité des noms en .cd pour WHMCS.
 *
 * Module « registrar » à choisir comme Lookup Provider
 * (Configuration > Paramètres système > Registraires de domaines > Lookup Provider).
 * Il interroge directement le WHOIS du registre .cd (whois.nic.cd, port 43) et
 * n'enregistre aucun domaine : les commandes se traitent à la main auprès du registre.
 *
 * Règle d'or : un domaine n'est affiché « disponible » que si le registre le dit
 * explicitement. Délai dépassé, refus, réponse vide ou inconnue : « inconnu ».
 *
 * @license MIT
 */

if (!defined('WHMCS')) {
    die('Accès direct interdit.');
}

require_once __DIR__ . '/lib/WhoisException.php';
require_once __DIR__ . '/lib/WhoisClient.php';
require_once __DIR__ . '/lib/ResponseParser.php';
require_once __DIR__ . '/lib/Store.php';

use LwbDomaineCd\ResponseParser;
use LwbDomaineCd\Store;
use LwbDomaineCd\WhoisClient;
use LwbDomaineCd\WhoisException;
use WHMCS\Domains\DomainLookup\ResultsList;
use WHMCS\Domains\DomainLookup\SearchResult;

const LWBDOMAINECD_MANUAL = 'Enregistrement manuel via le registre .cd : ce module sert uniquement à vérifier la disponibilité.';

function lwbdomainecd_MetaData()
{
    return [
        'DisplayName' => 'LWB Domaine .cd (vérification WHOIS)',
        'APIVersion' => '1.1',
    ];
}

function lwbdomainecd_getConfigArray()
{
    return [
        'FriendlyName' => [
            'Type' => 'System',
            'Value' => 'LWB Domaine .cd (vérification WHOIS)',
        ],
        'Description' => [
            'Type' => 'System',
            'Value' => 'Vérifie la disponibilité des noms en .cd directement auprès du registre. À choisir comme Lookup Provider. N\'enregistre aucun domaine.',
        ],
        'whoisServer' => [
            'FriendlyName' => 'Serveur WHOIS',
            'Type' => 'text',
            'Size' => '30',
            'Default' => 'whois.nic.cd',
        ],
        'whoisPort' => [
            'FriendlyName' => 'Port',
            'Type' => 'text',
            'Size' => '5',
            'Default' => '43',
        ],
        'timeout' => [
            'FriendlyName' => 'Délai d\'attente (secondes)',
            'Type' => 'text',
            'Size' => '5',
            'Default' => '5',
        ],
        'extensions' => [
            'FriendlyName' => 'Extensions .cd gérées',
            'Type' => 'textarea',
            'Rows' => '6',
            'Default' => ".cd\n.ac.cd\n.edu.cd\n.gouv.cd\n.com.cd\n.net.cd\n.org.cd",
            'Description' => 'Une par ligne. Ces extensions sont vérifiées auprès du registre.',
        ],
        'freePhrases' => [
            'FriendlyName' => 'Phrases « domaine libre »',
            'Type' => 'textarea',
            'Rows' => '5',
            'Default' => implode("\n", ResponseParser::DEFAULT_FREE_PHRASES),
            'Description' => 'Une par ligne. whois.nic.cd répond « Domain Status: No Object Found » pour un nom libre.',
        ],
        'reservedPhrases' => [
            'FriendlyName' => 'Phrases « réservé par le registre »',
            'Type' => 'textarea',
            'Rows' => '2',
            'Default' => implode("\n", ResponseParser::DEFAULT_RESERVED_PHRASES),
            'Description' => 'Une par ligne. Les statuts inactive et serverHold sont toujours traités comme non disponibles.',
        ],
        'cacheTakenMinutes' => [
            'FriendlyName' => 'Cache « pris / réservé » (minutes)',
            'Type' => 'text',
            'Size' => '5',
            'Default' => '10',
        ],
        'cacheFreeMinutes' => [
            'FriendlyName' => 'Cache « libre » (minutes)',
            'Type' => 'text',
            'Size' => '5',
            'Default' => '2',
        ],
        'rateLimit' => [
            'FriendlyName' => 'Requêtes WHOIS max. par minute et par IP',
            'Type' => 'text',
            'Size' => '5',
            'Default' => '20',
            'Description' => '0 = pas de limite. Les résultats en cache ne comptent pas.',
        ],
        'otherTlds' => [
            'FriendlyName' => 'Autres extensions (.com, .net…)',
            'Type' => 'yesno',
            'Default' => 'on',
            'Description' => 'Cochée : vérifiées par le WHOIS standard de WHMCS. Décochée : ignorées (elles n\'apparaissent plus dans les résultats).',
        ],
    ];
}

/** Extensions .cd gérées, en minuscules avec le point initial. */
function lwbdomainecd_extensions(array $params): array
{
    $text = trim((string) ($params['extensions'] ?? ''));
    if ($text === '') {
        $text = ".cd\n.ac.cd\n.edu.cd\n.gouv.cd\n.com.cd\n.net.cd\n.org.cd";
    }
    $out = [];
    foreach (preg_split('/[\s,]+/', strtolower($text)) ?: [] as $ext) {
        $ext = trim($ext);
        if ($ext !== '') {
            $out[] = '.' . ltrim($ext, '.');
        }
    }
    return array_values(array_unique($out));
}

function lwbdomainecd_client_ip(): string
{
    $ip = '';
    if (class_exists('\WHMCS\Utility\Environment\CurrentRequest')) {
        try {
            $ip = (string) \WHMCS\Utility\Environment\CurrentRequest::getIP();
        } catch (\Throwable $e) {
        }
    }
    if ($ip === '') {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'cli');
    }
    return substr($ip, 0, 45);
}

/**
 * Statut d'un domaine .cd : cache, puis limite de requêtes, puis WHOIS du registre.
 *
 * @return array{status: string, reason: string}
 */
function lwbdomainecd_check(string $domain, array $params): array
{
    $domain = strtolower(trim($domain));
    $server = trim((string) ($params['whoisServer'] ?? '')) ?: 'whois.nic.cd';
    $request = ['domaine' => $domain, 'serveur' => $server];

    try {
        Store::install();
        $cached = Store::get($domain);
        if ($cached !== null) {
            return ['status' => $cached, 'reason' => 'cache'];
        }
        if (!Store::allow(lwbdomainecd_client_ip(), (int) ($params['rateLimit'] ?? 20))) {
            logModuleCall('lwbdomainecd', 'whois', $request, 'Requête non envoyée : limite par minute atteinte pour ' . lwbdomainecd_client_ip(), ResponseParser::UNKNOWN);
            return ['status' => ResponseParser::UNKNOWN, 'reason' => 'limite de requêtes atteinte'];
        }
    } catch (\Throwable $e) {
        // Sans cache (base indisponible), on interroge quand même le registre.
        logModuleCall('lwbdomainecd', 'cache', $request, $e->getMessage(), 'cache ignoré');
    }

    $client = new WhoisClient($server, (int) ($params['whoisPort'] ?? 43) ?: 43, (float) ($params['timeout'] ?? 5) ?: 5.0);
    try {
        $raw = $client->query($domain);
    } catch (WhoisException $e) {
        logModuleCall('lwbdomainecd', 'whois', $request, $e->getMessage(), ResponseParser::UNKNOWN);
        return ['status' => ResponseParser::UNKNOWN, 'reason' => $e->getMessage()];
    }

    $parser = new ResponseParser(
        ResponseParser::phrasesFromText((string) ($params['freePhrases'] ?? ''), ResponseParser::DEFAULT_FREE_PHRASES),
        ResponseParser::phrasesFromText((string) ($params['reservedPhrases'] ?? ''), ResponseParser::DEFAULT_RESERVED_PHRASES)
    );
    $result = $parser->parse($domain, $raw);
    logModuleCall('lwbdomainecd', 'whois', $request, $raw, $result['status'] . ' : ' . $result['reason']);

    $minutes = 0;
    if ($result['status'] === ResponseParser::AVAILABLE) {
        $minutes = (int) ($params['cacheFreeMinutes'] ?? 2);
    } elseif ($result['status'] === ResponseParser::REGISTERED || $result['status'] === ResponseParser::RESERVED) {
        $minutes = (int) ($params['cacheTakenMinutes'] ?? 10);
    }
    try {
        Store::put($domain, $result['status'], $minutes);
    } catch (\Throwable $e) {
    }
    return $result;
}

/** Autres extensions : WHOIS standard de WHMCS (API DomainWhois). */
function lwbdomainecd_other_status(string $domain): string
{
    $r = localAPI('DomainWhois', ['domain' => $domain]);
    if (($r['result'] ?? '') !== 'success') {
        return ResponseParser::UNKNOWN;
    }
    return ($r['status'] ?? '') === 'available' ? ResponseParser::AVAILABLE : (($r['status'] ?? '') === 'unavailable' ? ResponseParser::REGISTERED : ResponseParser::UNKNOWN);
}

function lwbdomainecd_search_status(string $status): string
{
    switch ($status) {
        case ResponseParser::AVAILABLE:
            return SearchResult::STATUS_NOT_REGISTERED;
        case ResponseParser::REGISTERED:
            return SearchResult::STATUS_REGISTERED;
        case ResponseParser::RESERVED:
            return SearchResult::STATUS_RESERVED;
        default:
            return SearchResult::STATUS_UNKNOWN;
    }
}

/**
 * @param string[] $tlds
 */
function lwbdomainecd_results(string $sld, array $tlds, array $params, bool $includeOthers, bool $onlyAvailable = false): ResultsList
{
    $results = new ResultsList();
    $cd = lwbdomainecd_extensions($params);
    $sld = strtolower(trim($sld));
    if ($sld === '') {
        return $results;
    }
    foreach ($tlds as $tld) {
        $tld = '.' . ltrim(strtolower(trim((string) $tld)), '.');
        if (in_array($tld, $cd, true)) {
            $status = lwbdomainecd_check($sld . $tld, $params)['status'];
        } elseif ($includeOthers) {
            $status = lwbdomainecd_other_status($sld . $tld);
        } else {
            continue;
        }
        if ($onlyAvailable && $status !== ResponseParser::AVAILABLE) {
            continue;
        }
        $result = new SearchResult($sld, $tld);
        $result->setStatus(lwbdomainecd_search_status($status));
        $results->append($result);
    }
    return $results;
}

function lwbdomainecd_search_term(array $params): string
{
    if (!empty($params['isIdnDomain']) && !empty($params['punyCodeSearchTerm'])) {
        return (string) $params['punyCodeSearchTerm'];
    }
    return (string) ($params['searchTerm'] ?? '');
}

function lwbdomainecd_CheckAvailability($params)
{
    return lwbdomainecd_results(
        lwbdomainecd_search_term($params),
        (array) ($params['tldsToInclude'] ?? []),
        $params,
        !empty($params['otherTlds'])
    );
}

/** Nombre maximal d'extensions suggérées (chaque extension hors .cd coûte une requête WHOIS). */
const LWBDOMAINECD_MAX_SUGGESTIONS = 12;

/**
 * Réglages des suggestions, affichés dans la configuration du Lookup Provider.
 * Avec un module registraire, WHMCS ne transmet pas de liste d'extensions à suggérer.
 */
function lwbdomainecd_DomainSuggestionOptions()
{
    return [
        'suggestTlds' => [
            'FriendlyName' => 'Extensions suggérées',
            'Type' => 'text',
            'Size' => '60',
            'Default' => '.cd,.ac.cd,.gouv.cd,.edu.cd,.com,.net,.org,.biz,.info,.blog,.ca,.club',
            'Description' => 'Séparées par des virgules (' . LWBDOMAINECD_MAX_SUGGESTIONS . ' au maximum). Ne pas laisser vide : WHMCS ne demande des suggestions au module que si cette liste est remplie. Seuls les noms libres sont proposés.',
        ],
    ];
}

/**
 * Extensions à suggérer : celles transmises par WHMCS, sinon le réglage du module,
 * sinon la liste des suggestions WHOIS déjà configurée dans WHMCS.
 *
 * @return string[]
 */
function lwbdomainecd_suggestion_tlds(array $params): array
{
    $tlds = (array) ($params['tldsToInclude'] ?? []);
    if (!$tlds) {
        $text = trim((string) ($params['suggestionSettings']['suggestTlds'] ?? ''));
        if ($text === '') {
            try {
                $text = (string) \WHMCS\Database\Capsule::table('tbldomain_lookup_configuration')
                    ->where('registrar', 'WhmcsWhois')->where('setting', 'suggestTlds')->value('value');
            } catch (\Throwable $e) {
                $text = '';
            }
        }
        $tlds = preg_split('/[\s,]+/', $text !== '' ? $text : '.cd,.ac.cd,.gouv.cd,.edu.cd,.com,.net,.org') ?: [];
    }
    $out = [];
    foreach ($tlds as $tld) {
        $tld = '.' . ltrim(strtolower(trim((string) $tld)), '.');
        if ($tld !== '.' && !in_array($tld, $out, true)) {
            $out[] = $tld;
        }
    }
    return array_slice($out, 0, LWBDOMAINECD_MAX_SUGGESTIONS);
}

function lwbdomainecd_GetDomainSuggestions($params)
{
    $tlds = lwbdomainecd_suggestion_tlds($params);
    logModuleCall('lwbdomainecd', 'suggestions', [
        'recherche' => lwbdomainecd_search_term($params),
        'tldsToInclude' => $params['tldsToInclude'] ?? null,
        'suggestionSettings' => $params['suggestionSettings'] ?? null,
    ], implode(', ', $tlds), count($tlds) . ' extension(s)');
    // La page de commande de WHMCS affiche chaque suggestion comme disponible :
    // on ne renvoie donc que les noms réellement libres.
    return lwbdomainecd_results(lwbdomainecd_search_term($params), $tlds, $params, !empty($params['otherTlds']), true);
}

function lwbdomainecd_RegisterDomain($params)
{
    return ['error' => LWBDOMAINECD_MANUAL];
}

function lwbdomainecd_TransferDomain($params)
{
    return ['error' => LWBDOMAINECD_MANUAL];
}

function lwbdomainecd_RenewDomain($params)
{
    return ['error' => LWBDOMAINECD_MANUAL];
}
