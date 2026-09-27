<?php

declare(strict_types=1);

namespace Niang\Core;

/**
 * Repose sur la convention app/Models/User.php. Pour un autre modèle : Auth::useModel(MyUser::class).
 * Volontairement une simple classe statique (pas de "guards" multiples façon Laravel) : un site a une
 * seule notion d'utilisateur connecté dans l'immense majorité des cas.
 */
class Auth
{
    private const SESSION_KEY = '_auth_user_id';

    /**
     * Cookie chiffré de « se souvenir de moi » : « id|jeton ». Le jeton est en clair dans
     * users.remember_token pour être réutilisé par chaque appareil de l'utilisateur (un nouveau
     * jeton déconnecterait les autres) ; le cookie étant chiffré avec APP_KEY, lire la base ne
     * suffit pas à en fabriquer un.
     */
    public const REMEMBER_COOKIE = 'remember_web';

    /** 30 jours. */
    public const REMEMBER_MINUTES = 60 * 24 * 30;

    /** Mot de passe vérifié, code de double authentification attendu : ['id', 'remember', 'at']. */
    private const TWO_FACTOR_PENDING = '_auth_two_factor';

    /** Délai pour saisir le code après le mot de passe. */
    public const TWO_FACTOR_TIMEOUT = 300;

    private static string $model = 'App\\Models\\User';

    /**
     * Utilisateur résolu par jeton API (Bearer), pour la durée d'une requête — voir
     * App\Middleware\AuthenticateWithToken et Niang\Core\ApiToken. Prioritaire sur la session
     * dans id()/user() : une requête /api/* authentifiée par jeton ne doit pas hériter d'une
     * session de navigateur par ailleurs active dans le même process. Le middleware la
     * réinitialise dans un finally après chaque requête, jamais deux requêtes n'en héritent.
     */
    private static ?array $tokenUser = null;

    public static function useModel(string $model): void
    {
        self::$model = $model;
    }

    /** Le modèle utilisateur courant (App\Models\User par défaut, ou celui passé à useModel()). */
    public static function model(): string
    {
        return self::$model;
    }

    /** @internal utilisé par App\Middleware\AuthenticateWithToken, jamais appelé directement par une application. */
    public static function resolveViaToken(?array $user): void
    {
        self::$tokenUser = $user;
    }

    /**
     * Auth::attempt($email, $password, remember: true) pour « se souvenir de moi ». Un hachage
     * calculé avec d'anciens paramètres est recalculé au passage (Hash::needsRehash()).
     *
     * Si l'utilisateur a activé la double authentification, un mot de passe correct renvoie true
     * SANS connecter : Auth::twoFactorPending() devient vrai, et Auth::completeTwoFactor($code)
     * termine la connexion. Vérifiez twoFactorPending() après un attempt() réussi.
     */
    public static function attempt(
        string $email,
        string $password,
        string $emailField = 'email',
        string $passwordField = 'password',
        bool $remember = false
    ): bool {
        $model = self::$model;
        $user = $model::where($emailField, $email)[0] ?? null;

        if (!$user) {
            // Même coût qu'une vérification : sans ça, la durée de la réponse révèle si un compte
            // existe pour cet email.
            Hash::make($password);
            return false;
        }

        if (!Hash::check($password, $user[$passwordField])) {
            return false;
        }

        if (Hash::needsRehash($user[$passwordField])) {
            self::usersQuery('id', $user['id'])->update([$passwordField => Hash::make($password)]);
        }

        self::loginOrRequireTwoFactor($user, $remember);
        return true;
    }

    /**
     * Pour une identité déjà prouvée autrement que par le mot de passe (OAuth, lien magique...) :
     * connecte, sauf si la double authentification est activée — le code est alors exigé comme
     * après attempt() (vérifiez Auth::twoFactorPending()).
     */
    public static function loginOrRequireTwoFactor(array $user, bool $remember = false): void
    {
        if (TwoFactor::enabled($user)) {
            Session::regenerate();
            Session::forget(self::SESSION_KEY);
            Session::put(self::TWO_FACTOR_PENDING, ['id' => $user['id'], 'remember' => $remember, 'at' => time()]);

            return;
        }

        self::login($user, remember: $remember);
    }

    /** Vrai entre un attempt() réussi et la saisie du code, pendant TWO_FACTOR_TIMEOUT secondes. */
    public static function twoFactorPending(): bool
    {
        $pending = Session::get(self::TWO_FACTOR_PENDING);

        if (!is_array($pending)) {
            return false;
        }

        if (time() - (int) ($pending['at'] ?? 0) > self::TWO_FACTOR_TIMEOUT) {
            Session::forget(self::TWO_FACTOR_PENDING);
            return false;
        }

        return true;
    }

    /**
     * Code de l'application d'authentification, ou code de secours : connecte l'utilisateur mis
     * en attente par attempt(). Protégez la route par une limitation de débit (ThrottleRequests) :
     * un code à 6 chiffres ne résiste pas à des essais illimités.
     */
    public static function completeTwoFactor(string $code): bool
    {
        if (!self::twoFactorPending()) {
            return false;
        }

        $pending = Session::get(self::TWO_FACTOR_PENDING);
        $model = self::$model;
        $user = $model::find($pending['id']);

        if ($user === null || !TwoFactor::verify($user, $code)) {
            return false;
        }

        Session::forget(self::TWO_FACTOR_PENDING);
        self::login($user, remember: (bool) $pending['remember']);

        return true;
    }

    /**
     * Avec $remember, pose un cookie de 30 jours qui reconnecte l'utilisateur quand sa session a
     * expiré. Nécessite une colonne users.remember_token (voir la migration du framework).
     */
    public static function login(array $user, string $key = 'id', bool $remember = false): void
    {
        Session::regenerate();
        Session::put(self::SESSION_KEY, $user[$key]);

        if ($remember) {
            $token = $user['remember_token'] ?? null;

            if (!is_string($token) || strlen($token) < 32) {
                $token = bin2hex(random_bytes(32));
                self::usersQuery($key, $user[$key])->update(['remember_token' => $token]);
            }

            Cookie::queue(self::REMEMBER_COOKIE, $user[$key] . '|' . $token, self::REMEMBER_MINUTES);
        }
    }

    /** Déconnecte cet appareil ; les autres appareils mémorisés le restent (voir logoutEverywhere()). */
    public static function logout(): void
    {
        if (isset($_COOKIE[self::REMEMBER_COOKIE])) {
            self::forgetRememberCookie();
        }

        Session::forget(self::SESSION_KEY);
        Session::regenerate();
    }

    /**
     * Déconnecte cet appareil et invalide le « se souvenir de moi » de tous les autres (après un
     * vol de téléphone, un changement de mot de passe...). Les sessions déjà ouvertes ailleurs
     * durent jusqu'à leur expiration (SESSION_LIFETIME).
     */
    public static function logoutEverywhere(): void
    {
        $id = self::id();

        if ($id !== null) {
            self::usersQuery('id', $id)->update(['remember_token' => null]);
        }

        self::logout();
    }

    /**
     * Session expirée mais cookie « se souvenir de moi » présent : reconnecte si le jeton
     * correspond toujours à celui en base (il est effacé par logout()). Un cookie invalide est
     * supprimé, pour ne pas refaire la recherche à chaque appel.
     */
    private static function loginFromRememberCookie(): void
    {
        $value = Cookie::get(self::REMEMBER_COOKIE);

        if (!is_string($value) || !str_contains($value, '|')) {
            self::forgetRememberCookie();
            return;
        }

        [$id, $token] = explode('|', $value, 2);
        $model = self::$model;
        $user = $model::find($id);

        if ($user === null || !is_string($user['remember_token'] ?? null) || !hash_equals($user['remember_token'], $token)) {
            self::forgetRememberCookie();
            return;
        }

        Session::regenerate();
        Session::put(self::SESSION_KEY, $user['id']);
    }

    private static function forgetRememberCookie(): void
    {
        Cookie::queueForget(self::REMEMBER_COOKIE);
        unset($_COOKIE[self::REMEMBER_COOKIE]);
    }

    /** Écriture directe (pas Model::update()) : un changement de jeton ne doit pas toucher updated_at. */
    private static function usersQuery(string $key, int|string $id): Database\QueryBuilder
    {
        $model = self::$model;

        return $model::withTrashed()->where($key, $id);
    }

    public static function id(): int|string|null
    {
        if (self::$tokenUser !== null) {
            return self::$tokenUser['id'] ?? null;
        }

        if (Session::get(self::SESSION_KEY) === null && isset($_COOKIE[self::REMEMBER_COOKIE])) {
            self::loginFromRememberCookie();
        }

        return Session::get(self::SESSION_KEY);
    }

    public static function check(): bool
    {
        return self::id() !== null;
    }

    /**
     * Rôle de l'utilisateur connecté (config/permissions.php) : Auth::hasRole('admin'), ou ['admin', 'editor'].
     *
     * @param string|list<string> $roles
     */
    public static function hasRole(string|array $roles): bool
    {
        return Permission::hasRole(self::user(), $roles);
    }

    /** Gate::allows() pour l'utilisateur connecté : règle, Policy ou permission de rôle. */
    public static function can(string $ability, mixed ...$args): bool
    {
        return Gate::allows($ability, ...$args);
    }

    public static function guest(): bool
    {
        return !self::check();
    }

    public static function user(): ?array
    {
        if (self::$tokenUser !== null) {
            return self::$tokenUser;
        }

        $id = self::id();

        if ($id === null) {
            return null;
        }

        $model = self::$model;
        return $model::find($id);
    }
}
