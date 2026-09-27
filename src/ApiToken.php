<?php

declare(strict_types=1);

namespace Niang\Core;

use Niang\Core\Database\QueryBuilder;

/**
 * Authentification par jeton pour l'API (routes /api/*), sans session ni cookie — pour un client
 * qui n'est pas dans le même navigateur (app mobile, SPA découplée, script).
 *
 * Contrairement à un mot de passe (toujours vérifié dans le contexte d'un email déjà connu), un
 * jeton API doit être retrouvable à partir de sa seule valeur présentée par le client : la
 * recherche doit donc être indexée en base, ce qu'un hash salé façon Hash::make() ne permet pas
 * (deux hachages de la même valeur ne sont jamais égaux). HMAC-SHA256 avec APP_KEY comme clé —
 * même principe que UrlSignature — est déterministe et permet donc cette
 * recherche directe, tout en gardant le jeton en clair hors de la base. La haute entropie du
 * jeton (32 octets aléatoires, jamais choisi par un humain) rend un hash rapide suffisant, à la
 * différence d'un mot de passe.
 */
class ApiToken
{
    private const TABLE = 'personal_access_tokens';

    /**
     * Émet un nouveau jeton pour $user et le retourne en clair — la seule fois où il est
     * lisible : seul son hash est conservé en base.
     */
    public static function issue(array $user, string $name): string
    {
        $plaintext = bin2hex(random_bytes(32));

        self::query()->insert([
            'user_id' => $user['id'],
            'name' => $name,
            'token_hash' => self::hash($plaintext),
        ]);

        return $plaintext;
    }

    /** Retrouve l'utilisateur associé à un jeton en clair, ou null s'il est absent ou révoqué. */
    public static function resolve(string $plaintext): ?array
    {
        $record = self::query()->where('token_hash', self::hash($plaintext))->first();

        if ($record === null) {
            return null;
        }

        self::query()->where('id', $record['id'])->update(['last_used_at' => date('Y-m-d H:i:s')]);

        $model = Auth::model();
        return $model::find($record['user_id']);
    }

    /** Révoque un jeton (déconnexion d'un appareil) : sa ligne est supprimée. Faux s'il n'existait pas. */
    public static function revoke(string $plaintext): bool
    {
        $record = self::query()->where('token_hash', self::hash($plaintext))->first();

        if ($record === null) {
            return false;
        }

        self::query()->where('id', $record['id'])->delete();

        return true;
    }

    /** Révoque tous les jetons de $user (après un vol, un changement de mot de passe). @return int jetons révoqués */
    public static function revokeAll(array $user): int
    {
        $count = self::query()->where('user_id', $user['id'])->count();
        self::query()->where('user_id', $user['id'])->delete();

        return $count;
    }

    private static function hash(string $plaintext): string
    {
        return hash_hmac('sha256', $plaintext, AppKey::get());
    }

    private static function query(): QueryBuilder
    {
        return new QueryBuilder(self::TABLE);
    }
}
