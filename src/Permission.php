<?php

declare(strict_types=1);

namespace Niang\Core;

/**
 * Rôles et permissions déclarés dans config/permissions.php, sans table supplémentaire : un rôle
 * par utilisateur (colonne `role`), une liste de permissions par rôle. Gate::allows() s'en sert
 * quand aucune règle define() ni aucune Policy ne répond pour l'ability demandée.
 *
 * @experimental plusieurs rôles par utilisateur pourront être ajoutés.
 */
final class Permission
{
    public static function role(?array $user): ?string
    {
        $role = $user[(string) Config::get('permissions.column', 'role')] ?? null;

        return is_string($role) && $role !== '' ? $role : null;
    }

    /** @param string|list<string> $roles un rôle, ou plusieurs (l'un d'eux suffit) */
    public static function hasRole(?array $user, string|array $roles): bool
    {
        $role = self::role($user);

        return $role !== null && in_array($role, (array) $roles, true);
    }

    public static function can(?array $user, string $permission): bool
    {
        foreach (self::permissions($user) as $granted) {
            if ($granted === '*' || $granted === $permission) {
                return true;
            }

            if (str_ends_with($granted, '.*') && str_starts_with($permission, substr($granted, 0, -1))) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> permissions du rôle de l'utilisateur (vide pour un invité ou un rôle inconnu) */
    public static function permissions(?array $user): array
    {
        $role = self::role($user);
        $roles = Config::get('permissions.roles', []);

        return $role !== null && is_array($roles) && is_array($roles[$role] ?? null) ? array_values($roles[$role]) : [];
    }
}
