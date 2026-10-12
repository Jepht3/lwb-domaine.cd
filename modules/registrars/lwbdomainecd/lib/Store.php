<?php
/**
 * LWB Domaine .cd — cache des résultats et limitation des requêtes WHOIS.
 *
 * Deux petites tables, créées à la première utilisation :
 *  - mod_lwbdomainecd_cache : dernier statut connu de chaque domaine, avec expiration ;
 *  - mod_lwbdomainecd_rate  : nombre de requêtes WHOIS par IP et par minute.
 *
 * @license MIT
 */

namespace LwbDomaineCd;

use WHMCS\Database\Capsule;

final class Store
{
    public const CACHE_TABLE = 'mod_lwbdomainecd_cache';
    public const RATE_TABLE = 'mod_lwbdomainecd_rate';

    /** @var bool */
    private static $installed = false;

    public static function install(): void
    {
        if (self::$installed) {
            return;
        }
        $schema = Capsule::schema();
        if (!$schema->hasTable(self::CACHE_TABLE)) {
            $schema->create(self::CACHE_TABLE, function ($table) {
                $table->string('domain', 255)->primary();
                $table->string('status', 16);
                $table->dateTime('expires_at')->index();
            });
        }
        if (!$schema->hasTable(self::RATE_TABLE)) {
            $schema->create(self::RATE_TABLE, function ($table) {
                $table->string('ip', 45);
                $table->unsignedInteger('minute');
                $table->unsignedInteger('hits')->default(0);
                $table->primary(['ip', 'minute']);
            });
        }
        self::$installed = true;
    }

    /** Statut en cache encore valide, ou null. */
    public static function get(string $domain): ?string
    {
        $status = Capsule::table(self::CACHE_TABLE)
            ->where('domain', $domain)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->value('status');
        return $status !== null ? (string) $status : null;
    }

    public static function put(string $domain, string $status, int $minutes): void
    {
        if ($minutes <= 0) {
            return;
        }
        Capsule::table(self::CACHE_TABLE)->updateOrInsert(
            ['domain' => $domain],
            ['status' => $status, 'expires_at' => date('Y-m-d H:i:s', time() + $minutes * 60)]
        );
        // Ménage léger : une fois sur cinquante, on retire les entrées expirées.
        if (mt_rand(1, 50) === 1) {
            Capsule::table(self::CACHE_TABLE)->where('expires_at', '<', date('Y-m-d H:i:s'))->delete();
        }
    }

    /**
     * Compte une requête WHOIS pour cette IP et dit si elle reste sous la limite.
     *
     * @param int $perMinute 0 = pas de limite
     */
    public static function allow(string $ip, int $perMinute): bool
    {
        if ($perMinute <= 0) {
            return true;
        }
        $minute = (int) floor(time() / 60);
        $row = Capsule::table(self::RATE_TABLE)->where('ip', $ip)->where('minute', $minute)->first();
        if ($row) {
            Capsule::table(self::RATE_TABLE)->where('ip', $ip)->where('minute', $minute)->increment('hits');
            $hits = (int) $row->hits + 1;
        } else {
            Capsule::table(self::RATE_TABLE)->insert(['ip' => $ip, 'minute' => $minute, 'hits' => 1]);
            $hits = 1;
            Capsule::table(self::RATE_TABLE)->where('minute', '<', $minute - 5)->delete();
        }
        return $hits <= $perMinute;
    }
}
