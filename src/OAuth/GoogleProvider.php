<?php

declare(strict_types=1);

namespace Niang\Core\OAuth;

/** Google (OpenID Connect) : https://console.cloud.google.com/apis/credentials */
final class GoogleProvider extends Provider
{
    protected function defaultAuthorizeUrl(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth';
    }

    protected function defaultTokenUrl(): string
    {
        return 'https://oauth2.googleapis.com/token';
    }

    protected function scopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    public function user(string $accessToken): array
    {
        $data = $this->getJson($this->apiUrl('https://openidconnect.googleapis.com') . '/v1/userinfo', $accessToken);

        return [
            'id' => (string) ($data['sub'] ?? ''),
            'email' => isset($data['email']) ? (string) $data['email'] : null,
            'email_verified' => ($data['email_verified'] ?? false) === true,
            'name' => isset($data['name']) ? (string) $data['name'] : null,
            'avatar' => isset($data['picture']) ? (string) $data['picture'] : null,
            'raw' => $data,
        ];
    }
}
