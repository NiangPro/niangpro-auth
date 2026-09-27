<?php

declare(strict_types=1);

namespace Niang\Core;

class Hash
{
    public static function make(string $value): string
    {
        return password_hash($value, self::algorithm());
    }

    /**
     * Vrai si le hachage a été calculé avec un autre algorithme ou d'autres paramètres que ceux
     * d'aujourd'hui (ex. bcrypt d'une ancienne version de PHP, puis Argon2id disponible) : Auth::attempt()
     * le recalcule alors à la connexion, seul moment où le mot de passe en clair est connu.
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, self::algorithm());
    }

    private static function algorithm(): string
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    }

    public static function check(string $value, string $hash): bool
    {
        return password_verify($value, $hash);
    }
}
