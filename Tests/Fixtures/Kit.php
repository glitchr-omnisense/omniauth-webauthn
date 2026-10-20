<?php

namespace Omniauth\Passkey\Tests\Fixtures;

use Omniauth\ArrayState;
use Omniauth\CacheThrottle;
use Omniauth\Context;
use Omniauth\EmailCode\EmailCodeMethod;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Passkey\PasskeyMethod;
use Omniauth\Passkey\RelyingParty;
use Omniauth\Passkey\Testing\InMemoryPasskeys;
use Omniauth\Passkey\Testing\SoftwareAuthenticator;
use Omniauth\Password\PasswordMethod;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\RecordingSender;
use Omniauth\Testing\TestAccount;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

/**
 * omniauth with its passkeys, on the in-memory stores: two accounts (ringo;
 * paul, who also has the code by e-mail - a second factor a password asks
 * for, a passkey not), a password each, a fixed clock, a throttle, one
 * relying party (example.org, served on https://example.org unless told).
 */
final class Kit
{
    public const SECRET = 'a-kernel-secret-of-thirty-two-bytes-or-more';
    public const ORIGIN = 'https://example.org';

    public readonly FixedClock $clock;
    public readonly InMemoryStore $store;
    public readonly InMemoryPasskeys $passkeys;
    public readonly PasskeyMethod $passkey;
    public readonly TestAccount $ringo;
    public readonly TestAccount $paul;
    public readonly Omniauth $omniauth;
    /** @var array<string, mixed> */
    public array $session = [];

    public function __construct(RelyingParty $rp = new RelyingParty('example.org'))
    {
        $this->clock = new FixedClock();
        $hasher = new NativePasswordHasher(cost: 4);
        $this->store = new InMemoryStore(
            $this->ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine'), 'Ringo Starr'),
            $this->paul = new TestAccount('2', 'paul', 'paul@example.org', $hasher->hash('let-it-be'), 'Paul', emailCodeEnabled: true),
        );
        $this->passkeys = new InMemoryPasskeys($this->store);
        $this->passkey = new PasskeyMethod($this->store, $this->passkeys, $rp);
        $this->omniauth = new Omniauth(
            $this->store,
            new Methods([
                new PasswordMethod($this->store, $this->store, $hasher),
                new EmailCodeMethod($this->store, $this->store->emailCodes(), new RecordingSender(), self::SECRET, clock: $this->clock),
                $this->passkey,
            ]),
            new ArrayState($this->session),
            throttle: new CacheThrottle(new ArrayCache($this->clock), clock: $this->clock),
            clock: $this->clock,
        );
    }

    public static function context(string $origin = self::ORIGIN): Context
    {
        return new Context($origin, (string) parse_url($origin, \PHP_URL_HOST), '203.0.113.7');
    }

    /** Registers a passkey of $authenticator for $account from its settings, as a host's page would. */
    public function register(TestAccount $account, SoftwareAuthenticator $authenticator, ?Context $context = null, ?string $label = null): \Omniauth\Enrolled
    {
        $context ??= self::context();
        $enrolment = $this->omniauth->enrol('passkey', $account);
        $options = $enrolment->begin($context);
        if ('json' !== $options->kind) {
            throw new \RuntimeException('No creation options: '.$options->reason);
        }

        return $enrolment->confirm($context, ['json' => json_encode($authenticator->create($options->payload)), 'label' => $label]);
    }

    /** Signs in with the passkey of $authenticator, as assets/security/webauthn.js does. */
    public function signIn(SoftwareAuthenticator $authenticator, ?Context $context = null): \Omniauth\Result
    {
        $context ??= self::context();
        $options = $this->omniauth->begin('passkey', $context);
        if ('json' !== $options->kind) {
            throw new \RuntimeException('No request options: '.$options->reason);
        }

        return $this->omniauth->verify('passkey', $context, ['json' => json_encode($authenticator->get($options->payload))]);
    }
}
