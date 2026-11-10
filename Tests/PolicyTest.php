<?php

namespace Omniauth\WebAuthn\Tests;

use Omnisense\Contracts\Policy\Permission;
use Omnisense\Contracts\Policy\UsagePolicy;
use PHPUnit\Framework\TestCase;

/** Its usage policy, as data: no third party is called for the passkeys, so nothing is limited. */
final class PolicyTest extends TestCase
{
    public function testThePackageDeclaresNoThirdPartyAndItsLicence(): void
    {
        $policy = UsagePolicy::fromFile(__DIR__.'/../policy.json');

        self::assertSame('webauthn', $policy->provider);
        self::assertSame([], $policy->rateLimits, 'no service called: no limit');
        self::assertFalse($policy->requirements->key);
        self::assertSame(Permission::Allowed, $policy->rights->commercial);
        self::assertSame('MIT', $policy->rights->licence);
        self::assertSame('2026-11-10', $policy->provenance->verifiedAt);
        self::assertMatchesRegularExpression('~"omnisense": \{\s*"policy": "policy\.json"~', (string) file_get_contents(__DIR__.'/../composer.json'), 'composer.json names it');
    }
}
