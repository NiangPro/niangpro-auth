<?php

declare(strict_types=1);

namespace Niang\Core\OAuth;

use Niang\Core\Exceptions\OAuthException;
use Niang\Core\Http\Client;

/**
 * Un fournisseur OAuth 2 (flux « authorization code »). Les URLs sont celles du fournisseur réel ;
 * config/oauth.php peut les remplacer (serveur de test, instance GitHub Enterprise...).
 */
abstract class Provider
{
    /** @param array{client_id: string, client_secret: string, redirect: string, authorize_url?: string, token_url?: string, api_url?: string} $config */
    public function __construct(protected array $config)
    {
    }

    abstract protected function defaultAuthorizeUrl(): string;

    abstract protected function defaultTokenUrl(): string;

    /** @return list<string> */
    abstract protected function scopes(): array;

    /**
     * Profil normalisé : identifiant chez le fournisseur, email, et surtout email_verified — seul un
     * email vérifié par le fournisseur peut rattacher la connexion à un compte existant.
     *
     * @return array{id: string, email: ?string, email_verified: bool, name: ?string, avatar: ?string, raw: array<string, mixed>}
     */
    abstract public function user(string $accessToken): array;

    public function authorizeUrl(string $state, string $codeChallenge): string
    {
        return ($this->config['authorize_url'] ?? $this->defaultAuthorizeUrl()) . '?' . http_build_query([
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $this->config['redirect'],
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes()),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /** Échange le code reçu au retour contre un jeton d'accès. */
    public function accessToken(string $code, string $codeVerifier): string
    {
        $response = Client::postForm($this->config['token_url'] ?? $this->defaultTokenUrl(), [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config['redirect'],
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret'],
            'code_verifier' => $codeVerifier,
        ], ['Accept' => 'application/json']);

        $data = json_decode($response['body'], true);

        if ($response['status'] !== 200 || !is_array($data) || !is_string($data['access_token'] ?? null)) {
            $error = is_array($data) ? (string) ($data['error_description'] ?? $data['error'] ?? '') : '';
            throw new OAuthException("Échange du code refusé par le fournisseur (HTTP {$response['status']}" . ($error !== '' ? " : $error" : '') . ').');
        }

        return $data['access_token'];
    }

    /** @return array<string, mixed> */
    protected function getJson(string $url, string $accessToken): array
    {
        $response = Client::request('GET', $url, ['Authorization' => "Bearer $accessToken", 'Accept' => 'application/json']);
        $data = json_decode($response['body'], true);

        if ($response['status'] !== 200 || !is_array($data)) {
            throw new OAuthException("Profil inaccessible chez le fournisseur (HTTP {$response['status']}).");
        }

        return $data;
    }

    protected function apiUrl(string $default): string
    {
        return rtrim($this->config['api_url'] ?? $default, '/');
    }
}
