<?php

declare(strict_types=1);

namespace Niang\Core;

/**
 * Deux façons d'enregistrer une règle, au choix :
 *  - define() : une closure par règle, pour une vérification isolée (ex: 'view-admin').
 *  - policy() : une classe par ressource, quand plusieurs règles s'accumulent autour d'un même
 *    modèle (ex: PostPolicy avec delete()/update()...) — évite une longue liste de closures.
 * Les enregistrements restant de simples tableaux (pas d'objets), il n'y a pas de classe à
 * inspecter pour deviner la policy : le préfixe de l'ability ('post.delete' -> 'post') le dit
 * explicitement, résolu vers la méthode du même nom sur la policy enregistrée.
 * Sans règle ni Policy pour l'ability, les permissions de rôle (Permission) décident.
 */
class Gate
{
    private static array $abilities = [];

    /** @var array<string, string> préfixe d'ability (ex: 'post') -> classe Policy */
    private static array $policies = [];

    public static function define(string $ability, \Closure $callback): void
    {
        self::$abilities[$ability] = $callback;
    }

    /** Gate::policy('post', PostPolicy::class) -> 'post.delete' résout vers PostPolicy::delete(). */
    public static function policy(string $prefix, string $policyClass): void
    {
        self::$policies[$prefix] = $policyClass;
    }

    public static function allows(string $ability, mixed ...$args): bool
    {
        if (isset(self::$abilities[$ability])) {
            return (bool) (self::$abilities[$ability])(Auth::user(), ...$args);
        }

        [$prefix, $method] = array_pad(explode('.', $ability, 2), 2, null);

        if ($method !== null && isset(self::$policies[$prefix])) {
            $policyClass = self::$policies[$prefix];

            if (method_exists($policyClass, $method)) {
                return (bool) (new $policyClass())->$method(Auth::user(), ...$args);
            }
        }

        // Aucune règle ni Policy : les permissions du rôle de l'utilisateur (config/permissions.php).
        return Permission::can(Auth::user(), $ability);
    }

    /** @internal efface règles et Policies — appelée par TestCase entre deux tests. */
    public static function reset(): void
    {
        self::$abilities = [];
        self::$policies = [];
    }

    public static function denies(string $ability, mixed ...$args): bool
    {
        return !self::allows($ability, ...$args);
    }
}
