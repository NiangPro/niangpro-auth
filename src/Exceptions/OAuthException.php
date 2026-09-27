<?php

declare(strict_types=1);

namespace Niang\Core\Exceptions;

/** État invalide (CSRF), accès refusé par l'utilisateur, code rejeté, fournisseur inconnu... */
class OAuthException extends \RuntimeException
{
}
