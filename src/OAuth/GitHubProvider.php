<?php

declare(strict_types=1);

namespace Niang\Core\OAuth;

/**
 * GitHub : https://github.com/settings/developers. L'email du profil public peut être absent ou non
 * vérifié : l'adresse principale et vérifiée est lue sur /user/emails (portée user:email).
 */
final class GitHubProvider extends Provider
{
    protected function defaultAuthorizeUrl(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function defaultTokenUrl(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function scopes(): array
    {
        return ['read:user', 'user:email'];
    }

    public function user(string $accessToken): array
    {
        $api = $this->apiUrl('https://api.github.com');
        $data = $this->getJson("$api/user", $accessToken);
        $primary = null;

        foreach ($this->getJson("$api/user/emails", $accessToken) as $email) {
            if (is_array($email) && ($email['primary'] ?? false) === true) {
                $primary = $email;
                break;
            }
        }

        return [
            'id' => (string) ($data['id'] ?? ''),
            'email' => isset($primary['email']) ? (string) $primary['email'] : null,
            'email_verified' => ($primary['verified'] ?? false) === true,
            'name' => isset($data['name']) ? (string) $data['name'] : (isset($data['login']) ? (string) $data['login'] : null),
            'avatar' => isset($data['avatar_url']) ? (string) $data['avatar_url'] : null,
            'raw' => $data,
        ];
    }
}
