<?php

declare(strict_types=1);

namespace Niang\Core;

/**
 * Codes à usage unique basés sur le temps (TOTP, RFC 6238 ; HOTP, RFC 4226) : ceux des applications
 * Google Authenticator, Microsoft Authenticator, Aegis, 1Password... Paramètres compatibles avec
 * toutes : SHA-1, 6 chiffres, 30 secondes. Aucune dépendance.
 *
 * Voir TwoFactor pour l'usage avec un compte utilisateur (secret chiffré, anti-rejeu, codes de secours).
 */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;

    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Secret aléatoire de 160 bits (la taille recommandée par la RFC 4226), encodé en base32. */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    /** Code valable à l'instant $timestamp (maintenant par défaut). */
    public static function code(string $secret, ?int $timestamp = null, int $digits = self::DIGITS): string
    {
        return self::hotp(self::base32Decode($secret), intdiv($timestamp ?? time(), self::PERIOD), $digits);
    }

    /**
     * Vérifie un code en tolérant $window périodes d'avance ou de retard (horloge du téléphone
     * décalée). Retourne le numéro de période reconnu (pour refuser un second usage du même code,
     * voir TwoFactor), ou null. Comparaison en temps constant.
     */
    public static function verify(string $secret, string $code, int $window = 1, ?int $timestamp = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';

        if (preg_match('/^\d{' . self::DIGITS . '}$/', $code) !== 1) {
            return null;
        }

        $key = self::base32Decode($secret);
        $current = intdiv($timestamp ?? time(), self::PERIOD);
        $matched = null;

        // Toutes les périodes sont calculées, même après une correspondance : durée constante.
        for ($step = $current - $window; $step <= $current + $window; $step++) {
            if (hash_equals(self::hotp($key, $step, self::DIGITS), $code) && $matched === null) {
                $matched = $step;
            }
        }

        return $matched;
    }

    /**
     * URI otpauth:// que les applications d'authentification importent (en QR code ou en lien sur
     * mobile). $account : l'email de l'utilisateur ; $issuer : le nom du site.
     */
    public static function provisioningUri(string $secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);

        return "otpauth://totp/$label?" . http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /** RFC 4226 : HMAC-SHA1 du compteur, troncature dynamique. */
    public static function hotp(string $key, int $counter, int $digits = self::DIGITS): string
    {
        $hash = hash_hmac('sha1', pack('J', $counter), $key, true);
        $offset = ord($hash[19]) & 0x0F;
        $value = ((ord($hash[$offset]) & 0x7F) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad((string) ($value % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $encoded = '';
        foreach (str_split($bits, 5) as $chunk) {
            $encoded .= self::BASE32[(int) bindec(str_pad($chunk, 5, '0'))];
        }

        return $encoded;
    }

    /** Accepte minuscules, espaces et « = » (saisie manuelle d'un secret). */
    public static function base32Decode(string $encoded): string
    {
        $encoded = strtoupper((string) preg_replace('/[\s=]/', '', $encoded));

        if ($encoded === '' || strspn($encoded, self::BASE32) !== strlen($encoded)) {
            throw new \InvalidArgumentException('Secret TOTP invalide (base32 attendu).');
        }

        $bits = '';
        foreach (str_split($encoded) as $char) {
            $bits .= str_pad(decbin((int) strpos(self::BASE32, $char)), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr((int) bindec($byte));
            }
        }

        return $bytes;
    }
}
