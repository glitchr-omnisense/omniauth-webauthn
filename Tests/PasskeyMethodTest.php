<?php

namespace Omniauth\Passkey\Tests;

use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Passkey\PasskeyRecord;
use Omniauth\Passkey\RelyingParty;
use Omniauth\Passkey\Testing\SoftwareAuthenticator;
use Omniauth\Passkey\Tests\Fixtures\Kit;
use Omniauth\Status;
use PHPUnit\Framework\TestCase;

/**
 * Passkeys through the conductor, a software authenticator in the
 * browser's place: a registration from the settings, then a sign-in with no
 * second factor; the options' JSON; every refusal - a forged signature, an
 * unknown passkey, a challenge used twice, another origin, another relying
 * party, a person not verified, a counter gone back; the counter and the
 * backup flags kept; one relying party for two hosts (QA9).
 */
final class PasskeyMethodTest extends TestCase
{
    public function testAPasskeyRegisteredFromTheSettingsSignsIn(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);

        self::assertTrue($kit->register($kit->ringo, $authenticator, label: 'MacBook Touch ID')->isDone());

        $record = $kit->passkeys->byCredentialId(base64_encode($authenticator->credentialId));
        self::assertInstanceOf(PasskeyRecord::class, $record);
        self::assertSame(['1', 1, ['internal'], 'none', [], PasskeyRecord::NO_AAGUID, false, false, true], [$record->userHandle, $record->counter, $record->transports, $record->attestationType, $record->trustPath, $record->aaguid, $record->backupEligible, $record->backupStatus, $record->uvInitialized]);
        self::assertSame($authenticator->publicKey(), $record->publicKey());
        self::assertSame('MacBook Touch ID', $kit->passkeys->labels[$record->publicKeyCredentialId]);

        $result = $kit->signIn($authenticator);

        self::assertTrue($result->isAuthenticated());
        self::assertSame($kit->ringo, $result->account);
        self::assertSame([Factor::Passkey], $result->passed);
        self::assertSame(2, $kit->passkeys->byCredentialId($record->publicKeyCredentialId)->counter, 'the counter the authenticator signed, saved');
    }

    public function testNoSecondFactorIsAskedAfterAPasskey(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->paul, $authenticator);

        self::assertTrue($kit->omniauth->verify('password', Kit::context(), ['identifier' => 'paul', 'password' => 'let-it-be'])->needsSecondFactor(), 'a password asks for paul\'s code by e-mail');
        $kit->omniauth->abandon();

        $result = $kit->signIn($authenticator);
        self::assertSame([Status::Authenticated, [Factor::Passkey]], [$result->status, $result->passed], 'QA1: a passkey asks for none');
    }

    public function testTheRequestOptionsAreWebauthnLibsJson(): void
    {
        $kit = new Kit();

        $challenge = $kit->omniauth->begin('passkey', Kit::context());

        self::assertSame('json', $challenge->kind);
        $options = json_decode($challenge->payload, true);
        self::assertSame(['challenge', 'rpId', 'allowCredentials', 'userVerification'], array_keys($options));
        self::assertSame([], $options['allowCredentials'], 'a discoverable passkey: no account named, the person picks it');
        self::assertSame(['example.org', 'required'], [$options['rpId'], $options['userVerification']]);
        self::assertSame(32, \strlen(SoftwareAuthenticator::decode($options['challenge'])));
        self::assertMatchesRegularExpression('~^[A-Za-z0-9_-]{43}$~', $options['challenge'], 'base64url, unpadded: what parseRequestOptionsFromJSON() reads');
        self::assertNotSame($options['challenge'], json_decode($kit->omniauth->begin('passkey', Kit::context())->payload, true)['challenge'], 'a new challenge each time');
    }

    public function testTheCreationOptionsNameTheAccountAndExcludeItsPasskeys(): void
    {
        $kit = new Kit(new RelyingParty('example.org', 'Les Ringo Stars'));
        $first = new SoftwareAuthenticator(Kit::ORIGIN);
        $options = json_decode($kit->omniauth->enrol('passkey', $kit->ringo)->begin(Kit::context())->payload, true);

        self::assertSame(['id' => 'example.org', 'name' => 'Les Ringo Stars'], $options['rp']);
        self::assertSame(['1', 'ringo', 'Ringo Starr'], [SoftwareAuthenticator::decode($options['user']['id']), $options['user']['name'], $options['user']['displayName']], 'the handle as the user\'s id, as WebauthnUserEntityRepository gives it');
        self::assertSame([['type' => 'public-key', 'alg' => -7], ['type' => 'public-key', 'alg' => -257]], $options['pubKeyCredParams']);
        self::assertSame(['requireResidentKey' => true, 'userVerification' => 'required', 'residentKey' => 'required'], $options['authenticatorSelection']);
        self::assertSame('none', $options['attestation']);
        self::assertSame([], $options['excludeCredentials']);

        $kit->register($kit->ringo, $first);
        $options = json_decode($kit->omniauth->enrol('passkey', $kit->ringo)->begin(Kit::context())->payload, true);
        self::assertSame([['type' => 'public-key', 'id' => SoftwareAuthenticator::encode($first->credentialId), 'transports' => ['internal']]], $options['excludeCredentials']);
    }

    public function testTheSameAuthenticatorIsNotRegisteredTwice(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);

        $again = $kit->register($kit->ringo, $authenticator);

        self::assertSame([Failure::BadCredentials, 'known-passkey'], [$again->failure, $again->reason]);
        self::assertCount(1, $kit->passkeys->records);
    }

    public function testAForgedSignatureSignsNobodyIn(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $impostor = (new SoftwareAuthenticator(Kit::ORIGIN, credentialId: $authenticator->credentialId))->belongsTo('1');

        $result = $kit->signIn($impostor);

        self::assertSame([Status::Failed, Failure::BadCredentials, 'invalid-assertion'], [$result->status, $result->failure, $result->reason]);
        self::assertSame(1, $kit->passkeys->byCredentialId(base64_encode($authenticator->credentialId))->counter, 'nothing saved');
        self::assertTrue($kit->signIn($authenticator)->isAuthenticated(), 'the registered one does');
    }

    public function testAnUnknownPasskeySignsNobodyIn(): void
    {
        $kit = new Kit();
        $kit->register($kit->ringo, new SoftwareAuthenticator(Kit::ORIGIN));

        $result = $kit->signIn((new SoftwareAuthenticator(Kit::ORIGIN))->belongsTo('1'));

        self::assertSame([Failure::BadCredentials, 'unknown-passkey'], [$result->failure, $result->reason]);
    }

    public function testAChallengeServesOnce(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $options = $kit->omniauth->begin('passkey', Kit::context());
        $assertion = json_encode($authenticator->get($options->payload));

        self::assertTrue($kit->omniauth->verify('passkey', Kit::context(), ['json' => $assertion])->isAuthenticated());
        self::assertSame(Failure::Expired, $kit->omniauth->verify('passkey', Kit::context(), ['json' => $assertion])->failure, 'the same assertion again: its challenge is gone');
    }

    public function testNoBeginningNoSignIn(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);

        $assertion = $authenticator->get(['challenge' => SoftwareAuthenticator::encode(random_bytes(32)), 'rpId' => 'example.org']);

        self::assertSame(Failure::Expired, $kit->omniauth->verify('passkey', Kit::context(), $assertion)->failure, 'the proof may be the JSON\'s keys as well');
    }

    public function testAnotherChallengeIsRefused(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $kit->omniauth->begin('passkey', Kit::context());

        $result = $kit->omniauth->verify('passkey', Kit::context(), $authenticator->get(['challenge' => SoftwareAuthenticator::encode(random_bytes(32)), 'rpId' => 'example.org']));

        self::assertSame('invalid-assertion', $result->reason);
    }

    public function testAnotherOriginIsRefused(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $phishing = new SoftwareAuthenticator('https://example.org.evil.test', $authenticator->privateKey(), $authenticator->credentialId, counter: 5);

        $result = $kit->signIn($phishing->belongsTo('1'));

        self::assertSame('invalid-assertion', $result->reason, 'the client data names an origin the site does not have');
    }

    public function testAPasskeyOfAnotherRelyingPartyIsRefused(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $options = json_decode($kit->omniauth->begin('passkey', Kit::context())->payload, true);
        $options['rpId'] = 'evil.test';   // signed for another relying party

        $result = $kit->omniauth->verify('passkey', Kit::context(), $authenticator->get($options));

        self::assertSame('invalid-assertion', $result->reason);
    }

    public function testAHostTheRelyingPartyDoesNotServeHasNoOptions(): void
    {
        $kit = new Kit();

        $challenge = $kit->omniauth->begin('passkey', new Context('https://evil.test', 'evil.test'));

        self::assertSame([true, Failure::Refused, 'relying-party'], [$challenge->hasFailed(), $challenge->failure, $challenge->reason]);
    }

    public function testThePersonMustBeVerified(): void
    {
        $kit = new Kit();
        $unverified = new SoftwareAuthenticator(Kit::ORIGIN, verified: false);

        self::assertSame([Failure::BadCredentials, 'invalid-attestation'], [$kit->register($kit->ringo, $unverified)->failure, $kit->register($kit->ringo, $unverified)->reason], 'a registration without verification');

        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $authenticator->verified = false;
        self::assertSame('invalid-assertion', $kit->signIn($authenticator)->reason, 'a sign-in without verification');
    }

    public function testACounterGoneBackIsRefused(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        $kit->register($kit->ringo, $authenticator);
        $kit->signIn($authenticator);
        $kit->signIn($authenticator);
        self::assertSame(3, $kit->passkeys->byCredentialId(base64_encode($authenticator->credentialId))->counter);

        $clone = new SoftwareAuthenticator(Kit::ORIGIN, $authenticator->privateKey(), $authenticator->credentialId, counter: 1);
        $result = $kit->signIn($clone->belongsTo('1'));

        self::assertSame('invalid-assertion', $result->reason, 'a cloned authenticator: its counter is behind');
    }

    public function testTheBackupFlagsAreKept(): void
    {
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN, backupEligible: true);
        $kit->register($kit->ringo, $authenticator);
        $id = base64_encode($authenticator->credentialId);
        self::assertSame([true, false], [$kit->passkeys->byCredentialId($id)->backupEligible, $kit->passkeys->byCredentialId($id)->backupStatus]);

        $authenticator->backedUp = true;
        self::assertTrue($kit->signIn($authenticator)->isAuthenticated());

        self::assertSame([true, true], [$kit->passkeys->byCredentialId($id)->backupEligible, $kit->passkeys->byCredentialId($id)->backupStatus], 'synced since: the flag saved');
    }

    public function testOneRelyingPartyServesBothHosts(): void
    {
        // QA9: the site and its twin under one registrable domain; the id is that domain, both origins allowed.
        $kit = new Kit(new RelyingParty('example.org', origins: ['https://www.example.org', 'https://twin.example.org']));
        $authenticator = new SoftwareAuthenticator('https://www.example.org');
        self::assertTrue($kit->register($kit->ringo, $authenticator, Kit::context('https://www.example.org'))->isDone());

        $twin = new SoftwareAuthenticator('https://twin.example.org', $authenticator->privateKey(), $authenticator->credentialId, counter: $authenticator->counter);
        self::assertTrue($kit->signIn($twin->belongsTo('1'), Kit::context('https://twin.example.org'))->isAuthenticated(), 'registered on one host, signed in on the other');

        $other = new SoftwareAuthenticator('https://shop.example.org', $authenticator->privateKey(), $authenticator->credentialId, counter: 10);
        self::assertSame('invalid-assertion', $kit->signIn($other->belongsTo('1'), Kit::context('https://shop.example.org'))->reason, 'a third host under the domain is not among the origins');
    }

    public function testWithNoIdTheRequestsHostIsTheRelyingParty(): void
    {
        $kit = new Kit(new RelyingParty());
        $authenticator = new SoftwareAuthenticator('https://localhost:8443');
        $context = new Context('https://localhost:8443', 'localhost:8443');

        self::assertSame('localhost', json_decode($kit->omniauth->begin('passkey', $context)->payload, true)['rpId'], 'the port never enters the id');
        self::assertTrue($kit->register($kit->ringo, $authenticator, $context)->isDone());

        $laravel = new SoftwareAuthenticator('http://localhost:8132', $authenticator->privateKey(), $authenticator->credentialId, counter: $authenticator->counter);
        self::assertTrue($kit->signIn($laravel->belongsTo('1'), new Context('http://localhost:8132', 'localhost:8132'))->isAuthenticated(), 'the same passkey on the twin\'s port: localhost may be plain http');
    }

    public function testAnUnreadableCredentialIsRefused(): void
    {
        $kit = new Kit();
        $kit->omniauth->begin('passkey', Kit::context());

        self::assertSame('unreadable-credential', $kit->omniauth->verify('passkey', Kit::context(), ['json' => '{"id": "nothing"}'])->reason);
    }
}
