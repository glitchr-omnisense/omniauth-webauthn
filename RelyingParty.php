<?php

namespace Omniauth\Passkey;

use Omniauth\Context;

/**
 * Who the passkeys belong to: the relying party's id (a registrable domain:
 * a passkey made for it serves every host under it), the name some
 * authenticators show, and the origins a ceremony may come from.
 *
 * By Marco's decision QA9 (2026-10-20), the Symfony site and its Laravel twin
 * share one registrable domain in production: the id is that domain
 * (RELYING_PARTY_ID), and the origins are both hosts'. With no id, each
 * request's host is the id; with no origins, each request's origin is the only
 * one allowed. The port never enters the id ("localhost" for
 * https://localhost:8443 and http://localhost:8132 alike).
 */
final readonly class RelyingParty
{
    /**
     * @param list<string> $origins  the origins allowed (https://www.example.org, https://twin.example.org), [] for the request's own
     * @param list<string> $insecure the ids allowed over plain http (WebAuthn's own exception: localhost)
     */
    public function __construct(
        public ?string $id = null,
        public ?string $name = null,
        public array $origins = [],
        public array $insecure = ['localhost'],
    ) {
    }

    /** The relying party's id for this request: the one set, else the request's host (lower case, no port). */
    public function id(Context $context): string
    {
        return strtolower($this->id ?? self::host($context->host));
    }

    /** The name an authenticator shows: the one set, else the id (as web-auth/webauthn-symfony-bundle without `rp.name`). */
    public function name(Context $context): string
    {
        return $this->name ?? $this->id($context);
    }

    /** @return list<string> */
    public function origins(Context $context): array
    {
        return $this->origins ?: ('' !== $context->origin ? [$context->origin] : []);
    }

    /**
     * May this request's host use the id? WebAuthn asks the id to be the
     * host or a domain it is under (a browser refuses otherwise).
     */
    public function serves(Context $context): bool
    {
        $id = $this->id($context);
        $host = strtolower(self::host($context->host));

        return '' !== $id && ($host === $id || str_ends_with($host, '.'.$id));
    }

    private static function host(string $host): string
    {
        // "example.org:8443" -> "example.org"; "[::1]:8443" stays an address (and is no relying party).
        return preg_replace('~:\d+$~', '', $host) ?? $host;
    }
}
