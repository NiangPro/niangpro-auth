<?php

declare(strict_types=1);

namespace Niang\Core;

use Niang\Core\Exceptions\OAuthException;
use Niang\Core\Http\Request;
use Niang\Core\Http\Response;
use Niang\Core\OAuth\GitHubProvider;
use Niang\Core\OAuth\GoogleProvider;
use Niang\Core\OAuth\Provider;

/**
 * Connexion avec un compte Google ou GitHub (OAuth 2, flux « authorization code »), sans dépendance :
 *
 *   OAuth::redirect('github');              // vers la page d'autorisation du fournisseur
 *   $profil = OAuth::user('github', $request); // au retour : ['id', 'email', 'email_verified', ...]
 *
 * Protections : `state` aléatoire à usage unique gardé en session (un lien de retour forgé par un
 * tiers est refusé) et PKCE (le code intercepté ne sert à rien sans le secret gardé en session).
 * Configuration : config/oauth.php (GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID...).
 *
 * @experimental la liste des fournisseurs et la forme du profil peuvent encore évoluer.
 */
final class OAuth
{
    private const PROVIDERS = ['google' => GoogleProvider::class, 'github' => GitHubProvider::class];
    private const SESSION_KEY = '_oauth';

    public static function redirect(string $provider): Response
    {
        $instance = self::provider($provider);
        $state = bin2hex(random_bytes(20));
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        Session::put(self::SESSION_KEY, ['provider' => $provider, 'state' => $state, 'verifier' => $verifier]);

        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return Response::redirect($instance->authorizeUrl($state, $challenge));
    }

    /**
     * À appeler sur l'URL de retour. Lève une OAuthException si l'utilisateur a refusé, si l'état ne
     * correspond pas (lien forgé, retour rejoué, session expirée) ou si le fournisseur refuse le code.
     *
     * @return array{id: string, email: ?string, email_verified: bool, name: ?string, avatar: ?string, raw: array<string, mixed>}
     */
    public static function user(string $provider, Request $request): array
    {
        $pending = Session::get(self::SESSION_KEY);
        // À usage unique, même en cas d'échec : un même retour ne peut pas être rejoué.
        Session::forget(self::SESSION_KEY);

        if (is_string($request->input('error'))) {
            throw new OAuthException('Connexion annulée chez le fournisseur (' . $request->input('error') . ').');
        }

        $state = $request->input('state');

        if (
            !is_array($pending)
            || ($pending['provider'] ?? null) !== $provider
            || !is_string($state)
            || !hash_equals((string) ($pending['state'] ?? ''), $state)
        ) {
            throw new OAuthException('État OAuth invalide ou expiré : recommencez la connexion.');
        }

        $code = $request->input('code');

        if (!is_string($code) || $code === '') {
            throw new OAuthException('Code d\'autorisation absent du retour.');
        }

        $instance = self::provider($provider);
        $user = $instance->user($instance->accessToken($code, (string) $pending['verifier']));

        if ($user['id'] === '') {
            throw new OAuthException('Profil sans identifiant renvoyé par le fournisseur.');
        }

        return $user;
    }

    /** @return list<string> fournisseurs configurés (client_id renseigné) */
    public static function configured(): array
    {
        return array_values(array_filter(
            array_keys(self::PROVIDERS),
            fn (string $name) => (string) Config::get("oauth.$name.client_id", '') !== ''
        ));
    }

    private static function provider(string $name): Provider
    {
        $class = self::PROVIDERS[$name] ?? null;
        $config = Config::get("oauth.$name");

        if ($class === null) {
            throw new OAuthException("Fournisseur OAuth inconnu : « $name » (google, github).");
        }

        if (!is_array($config) || ($config['client_id'] ?? '') === '' || ($config['client_secret'] ?? '') === '') {
            throw new OAuthException("Fournisseur OAuth « $name » non configuré (client_id et client_secret dans config/oauth.php).");
        }

        $config['redirect'] = (string) ($config['redirect'] ?? '') !== ''
            ? (string) $config['redirect']
            : rtrim((string) Env::get('APP_URL', ''), '/') . "/auth/$name/callback";

        return new $class($config);
    }
}
