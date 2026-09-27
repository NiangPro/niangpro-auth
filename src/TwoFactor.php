<?php

declare(strict_types=1);

namespace Niang\Core;

use Niang\Core\Database\QueryBuilder;

/**
 * Double authentification (TOTP) d'un utilisateur. Colonnes de users (migration du framework) :
 *
 *  - two_factor_secret : le secret, chiffré avec APP_KEY (Crypt) — une fuite de la base seule ne
 *    permet pas de générer les codes ;
 *  - two_factor_confirmed_at : tant qu'elle est vide, la double authentification n'est pas exigée
 *    (l'utilisateur doit d'abord prouver, par un code, que son application est bien configurée) ;
 *  - two_factor_recovery_codes : empreintes SHA-256 des codes de secours, chacun à usage unique ;
 *  - two_factor_last_step : dernière période TOTP acceptée — un code intercepté ne peut pas être
 *    rejoué dans les 30 à 90 secondes où il reste valable.
 *
 * Le parcours de connexion est dans Auth (attempt() puis completeTwoFactor()).
 */
final class TwoFactor
{
    private const CRYPT_CONTEXT = 'two-factor';
    public const RECOVERY_CODES = 8;

    /**
     * Active (sans encore l'exiger) : nouveau secret et nouveaux codes de secours, à afficher UNE
     * fois à l'utilisateur. Confirmez ensuite avec confirm() et un code de son application.
     *
     * @return array{secret: string, uri: string, recovery_codes: list<string>}
     */
    public static function enable(array $user, ?string $issuer = null): array
    {
        $secret = Totp::generateSecret();
        $codes = self::newRecoveryCodes();

        self::users($user)->update([
            'two_factor_secret' => Crypt::encrypt($secret, self::CRYPT_CONTEXT),
            'two_factor_recovery_codes' => self::hashCodes($codes),
            'two_factor_confirmed_at' => null,
            'two_factor_last_step' => null,
        ]);

        $issuer ??= (string) Env::get('APP_NAME', 'NiangPro');

        return [
            'secret' => $secret,
            'uri' => Totp::provisioningUri($secret, (string) ($user['email'] ?? $user['id']), $issuer),
            'recovery_codes' => $codes,
        ];
    }

    /** Premier code correct : la double authentification devient obligatoire à la connexion. */
    public static function confirm(array $user, string $code): bool
    {
        $user = self::fresh($user);

        if ($user === null || !self::verifyTotp($user, $code)) {
            return false;
        }

        self::users($user)->update(['two_factor_confirmed_at' => date('Y-m-d H:i:s')]);

        return true;
    }

    public static function disable(array $user): void
    {
        self::users($user)->update([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
            'two_factor_last_step' => null,
        ]);
    }

    /** Vrai si la double authentification est confirmée, donc exigée à la connexion. */
    public static function enabled(array $user): bool
    {
        return !empty($user['two_factor_confirmed_at']) && !empty($user['two_factor_secret']);
    }

    /** Code de l'application (6 chiffres) ou code de secours (consommé). */
    public static function verify(array $user, string $code): bool
    {
        $user = self::fresh($user);

        if ($user === null || !self::enabled($user)) {
            return false;
        }

        return self::verifyTotp($user, $code) || self::useRecoveryCode($user, $code);
    }

    /** @return list<string> les nouveaux codes, à afficher une fois ; les anciens ne marchent plus. */
    public static function regenerateRecoveryCodes(array $user): array
    {
        $codes = self::newRecoveryCodes();
        self::users($user)->update(['two_factor_recovery_codes' => self::hashCodes($codes)]);

        return $codes;
    }

    public static function remainingRecoveryCodes(array $user): int
    {
        $user = self::fresh($user);

        return count(json_decode((string) ($user['two_factor_recovery_codes'] ?? '[]'), true) ?: []);
    }

    private static function verifyTotp(array $user, string $code): bool
    {
        $secret = Crypt::decrypt((string) ($user['two_factor_secret'] ?? ''), self::CRYPT_CONTEXT);

        if ($secret === null) {
            return false;
        }

        $step = Totp::verify($secret, $code);

        if ($step === null) {
            return false;
        }

        // Une seule requête conditionnelle : deux requêtes simultanées avec le même code ne
        // peuvent pas toutes deux réussir.
        $table = self::table();

        return Database\DB::affected(
            "UPDATE $table SET two_factor_last_step = ? WHERE id = ? AND (two_factor_last_step IS NULL OR two_factor_last_step < ?)",
            [$step, $user['id'], $step]
        ) === 1;
    }

    private static function useRecoveryCode(array $user, string $code): bool
    {
        $normalized = strtolower(preg_replace('/[\s-]/', '', $code) ?? '');
        $stored = json_decode((string) ($user['two_factor_recovery_codes'] ?? '[]'), true) ?: [];
        $hash = hash('sha256', $normalized);

        foreach ($stored as $index => $candidate) {
            if (is_string($candidate) && hash_equals($candidate, $hash)) {
                unset($stored[$index]);
                $remaining = json_encode(array_values($stored));
                $table = self::table();

                // Conditionnée à la valeur lue : un même code de secours ne sert qu'une fois,
                // même sur deux requêtes simultanées.
                return Database\DB::affected(
                    "UPDATE $table SET two_factor_recovery_codes = ? WHERE id = ? AND two_factor_recovery_codes = ?",
                    [$remaining, $user['id'], $user['two_factor_recovery_codes']]
                ) === 1;
            }
        }

        return false;
    }

    /** @return list<string> ex. « k7m2p-9xq4r » : 10 caractères aléatoires, sans caractères ambigus. */
    private static function newRecoveryCodes(): array
    {
        $alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
        $codes = [];

        for ($i = 0; $i < self::RECOVERY_CODES; $i++) {
            $code = '';
            for ($j = 0; $j < 10; $j++) {
                $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
            }
            $codes[] = substr($code, 0, 5) . '-' . substr($code, 5);
        }

        return $codes;
    }

    /** @param list<string> $codes */
    private static function hashCodes(array $codes): string
    {
        return (string) json_encode(array_map(fn (string $code) => hash('sha256', str_replace('-', '', $code)), $codes));
    }

    private static function fresh(array $user): ?array
    {
        $model = Auth::model();

        return isset($user['id']) ? $model::find($user['id']) : null;
    }

    private static function users(array $user): QueryBuilder
    {
        $model = Auth::model();

        return $model::withTrashed()->where('id', $user['id']);
    }

    private static function table(): string
    {
        $model = Auth::model();

        return $model::table();
    }
}
