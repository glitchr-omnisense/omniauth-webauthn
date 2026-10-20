<?php

namespace Omniauth\Passkey\Tests;

use Doctrine\DBAL\Platforms\MySQL80Platform;
use Doctrine\DBAL\Types\BooleanType;
use Doctrine\DBAL\Types\JsonType;
use Omniauth\Passkey\PasskeyRecord;
use Omniauth\Passkey\Testing\SoftwareAuthenticator;
use Omniauth\Passkey\Tests\Fixtures\Kit;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Doctrine\Type\AAGUIDDataType;
use Webauthn\Bundle\Doctrine\Type\Base64BinaryDataType;
use Webauthn\Bundle\Doctrine\Type\TrustPathDataType;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * Both ways with web-auth/webauthn-symfony-bundle, so that the switch (step
 * AU7, then every site) loses no passkey:
 *
 * - a passkey the bundle registered signs in through PasskeyMethod: the row
 *   lesringostars' sign-in suite (AU1) saw the bundle write at a
 *   registration from the settings - recorded here as it is - and, live, the
 *   row the bundle's DBAL types write for the record webauthn-lib's
 *   attestation check makes, as the bundle's creation controller does;
 * - a passkey PasskeyMethod registered is read by the bundle's DBAL types
 *   into the CredentialRecord the bundle verifies against, and webauthn-lib's
 *   assertion check, configured as the bundle configures it, signs in with it.
 *
 * The live tests need doctrine/dbal and the bundle (the harness installs
 * them); the recorded one needs neither.
 */
final class BundleCompatibilityTest extends TestCase
{
    /** The software authenticator of the recorded row: a P-256 key and a credential id, fixed. */
    private const KEY = <<<'PEM'
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSj2X/K0t8dWT/qav
        Vo19Wo+MSPpP0caRIBqYvcru5rihRANCAAR0ddpvQpJ4y5luRYTKFNiCO9RUx+jA
        Bp1IS6Za0E95GZa562152zKalAAfpJVTCy33HTEOZSz86ebIkcVHHRFy
        -----END PRIVATE KEY-----
        PEM;
    private const CREDENTIAL_ID = 'chGmTD4gUoBJXQ1d9WhAoViH7cMq7/i33VT1V37nKgg=';

    /**
     * userPasskey's 13 columns after the bundle registered this authenticator
     * for the account of id 1: the text lesringostars' PasskeySignInTest
     * (testAPasskeyAddedFromTheSettingsSignsIn, AU1) found in the table, as
     * MySQL gives it back (booleans 0/1).
     */
    private const ROW = [
        'publicKeyCredentialId' => self::CREDENTIAL_ID,
        'type' => 'public-key',
        'transports' => '["internal"]',
        'attestationType' => 'none',
        'trustPath' => '[]',
        'aaguid' => '00000000-0000-0000-0000-000000000000',
        'credentialPublicKey' => 'pQECAyYgASFYIHR12m9CknjLmW5FhMoU2II71FTH6MAGnUhLplrQT3kZIlgglrnrbXnbMpqUAB+klVMLLfcdMQ5lLPzp5siRxUcdEXI=',
        'userHandle' => '1',
        'counter' => 1,
        'otherUI' => null,
        'backupEligible' => 0,
        'backupStatus' => 0,
        'uvInitialized' => 1,
    ];

    public function testARowTheBundleWroteSignsInHere(): void
    {
        $kit = new Kit();
        $record = PasskeyRecord::fromRow(self::ROW + ['id' => 7, 'user_id' => 1, 'label' => null, 'createdAt' => '2026-10-20 10:00:00', 'lastUsedAt' => null]);
        $kit->passkeys->records[$record->publicKeyCredentialId] = $record;

        $result = $kit->signIn(self::authenticator(counter: 1));

        self::assertTrue($result->isAuthenticated(), (string) $result->reason);
        self::assertSame($kit->ringo, $result->account);
        self::assertSame(array_replace(self::ROW, ['counter' => 2]), $kit->passkeys->byCredentialId(self::CREDENTIAL_ID)->toRow(), 'the row written back: the counter moved, the rest as the bundle wrote it');
    }

    public function testTheBundlesTypesWriteThatRowAtARegistration(): void
    {
        self::needsTheBundle();
        $authenticator = self::authenticator();
        // The bundle's creation controller: its options (profile "default"), webauthn-lib's attestation check.
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('example.org', 'example.org'),
            PublicKeyCredentialUserEntity::create('ringo', '1', 'Ringo Starr'),
            random_bytes(32),
            authenticatorSelection: AuthenticatorSelectionCriteria::create(),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );
        $credential = self::serializer()->deserialize(json_encode($authenticator->create(self::normalized($options))), PublicKeyCredential::class, 'json');
        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);
        $made = AuthenticatorAttestationResponseValidator::create(self::bundleCeremonies()->creationCeremony())->check($credential->response, $options, 'example.org');

        self::assertSame(self::ROW, self::bundleRow($made), 'the bundle\'s types');
        self::assertSame(self::ROW, PasskeyRecord::fromCredentialRecord($made)->toRow(), 'and omniauth\'s record of the same, as omnibase\'s PasskeyRepository::fill() copies it');
    }

    public function testAPasskeyRegisteredHereIsReadAndVerifiedByTheBundle(): void
    {
        self::needsTheBundle();
        $kit = new Kit();
        $authenticator = new SoftwareAuthenticator(Kit::ORIGIN);
        self::assertTrue($kit->register($kit->ringo, $authenticator)->isDone());
        $row = $kit->passkeys->byCredentialId(base64_encode($authenticator->credentialId))->toRow();

        // What the bundle's repository gives its authenticator: the row through its DBAL types.
        $record = self::bundleRecord($row);
        self::assertSame($authenticator->credentialId, $record->publicKeyCredentialId);
        self::assertSame($authenticator->publicKey(), $record->credentialPublicKey);
        self::assertSame(['1', 1, 'none'], [$record->userHandle, $record->counter, $record->attestationType]);

        // The bundle's sign-in: its request options (profile "default"), webauthn-lib's assertion check as it configures it.
        $options = PublicKeyCredentialRequestOptions::create(random_bytes(32), 'example.org', userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);
        $credential = self::serializer()->deserialize(json_encode($authenticator->get(self::normalized($options))), PublicKeyCredential::class, 'json');
        self::assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
        $checked = AuthenticatorAssertionResponseValidator::create(self::bundleCeremonies()->requestCeremony())->check($record, $credential->response, $options, 'example.org', null);

        self::assertSame(2, $checked->counter);
        self::assertSame(array_replace($row, ['counter' => 2]), self::bundleRow($checked), 'what the bundle saves back is the row omniauth writes after the same sign-in');
        self::assertSame(self::bundleRow($checked), PasskeyRecord::fromRow($row)->after($checked)->toRow());
    }

    public function testACertificateTrustPathIsKeptAsTheBundleKeepsIt(): void
    {
        self::needsTheBundle();
        $made = CredentialRecord::create(random_bytes(16), 'public-key', ['usb', 'nfc'], 'basic', CertificateTrustPath::create(['MIIB/w==', 'MIIC']), Uuid::fromString('ee882879-721c-4913-9775-3dfcce97072a'), random_bytes(77), '42', 3, null, true, true, true);

        $row = PasskeyRecord::fromCredentialRecord($made)->toRow();

        self::assertSame(self::bundleRow($made), $row);
        self::assertSame('{"x5c":["MIIB\/w==","MIIC"]}', $row['trustPath']);
        self::assertEquals($made, PasskeyRecord::fromRow($row)->toCredentialRecord(), 'read back, the same record');
        self::assertEquals($made, self::bundleRecord($row));
    }

    private static function authenticator(int $counter = 0): SoftwareAuthenticator
    {
        return (new SoftwareAuthenticator(Kit::ORIGIN, self::KEY, base64_decode(self::CREDENTIAL_ID), $counter))->belongsTo('1');
    }

    /** The 13 columns as the bundle's Doctrine mapping writes a CredentialRecord (base64, aaguid, trust_path, json, boolean), on MySQL. */
    private static function bundleRow(CredentialRecord $record): array
    {
        $platform = new MySQL80Platform();
        $bool = static fn (?bool $value) => null === $value ? null : (new BooleanType())->convertToDatabaseValue($value, $platform);

        return [
            'publicKeyCredentialId' => (new Base64BinaryDataType())->convertToDatabaseValue($record->publicKeyCredentialId, $platform),
            'type' => $record->type,
            'transports' => (new JsonType())->convertToDatabaseValue($record->transports, $platform),
            'attestationType' => $record->attestationType,
            'trustPath' => (new TrustPathDataType())->convertToDatabaseValue($record->trustPath, $platform),
            'aaguid' => (new AAGUIDDataType())->convertToDatabaseValue($record->aaguid, $platform),
            'credentialPublicKey' => (new Base64BinaryDataType())->convertToDatabaseValue($record->credentialPublicKey, $platform),
            'userHandle' => $record->userHandle,
            'counter' => $record->counter,
            'otherUI' => null === $record->otherUI ? null : (new JsonType())->convertToDatabaseValue($record->otherUI, $platform),
            'backupEligible' => $bool($record->backupEligible),
            'backupStatus' => $bool($record->backupStatus),
            'uvInitialized' => $bool($record->uvInitialized),
        ];
    }

    /** A row read through the bundle's Doctrine mapping: the CredentialRecord its repository hands its authenticator. */
    private static function bundleRecord(array $row): CredentialRecord
    {
        $platform = new MySQL80Platform();
        $bool = static fn (mixed $value) => null === $value ? null : (new BooleanType())->convertToPHPValue($value, $platform);

        return CredentialRecord::create(
            (new Base64BinaryDataType())->convertToPHPValue($row['publicKeyCredentialId'], $platform),
            $row['type'],
            (new JsonType())->convertToPHPValue($row['transports'], $platform),
            $row['attestationType'],
            (new TrustPathDataType())->convertToPHPValue($row['trustPath'], $platform),
            (new AAGUIDDataType())->convertToPHPValue($row['aaguid'], $platform),
            (new Base64BinaryDataType())->convertToPHPValue($row['credentialPublicKey'], $platform),
            $row['userHandle'],
            (int) $row['counter'],
            null === $row['otherUI'] ? null : (new JsonType())->convertToPHPValue($row['otherUI'], $platform),
            $bool($row['backupEligible']),
            $bool($row['backupStatus']),
            $bool($row['uvInitialized']),
        );
    }

    /** webauthn-lib's ceremonies as the bundle builds them for a site with no `allowed_origins` (every site today). */
    private static function bundleCeremonies(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setSecuredRelyingPartyId([]);

        return $factory;
    }

    private static function serializer(): \Symfony\Component\Serializer\Serializer
    {
        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    /** The options as the bundle's options handler gives them to the browser. */
    private static function normalized(object $options): array
    {
        return self::serializer()->normalize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
    }

    private static function needsTheBundle(): void
    {
        if (!class_exists(Base64BinaryDataType::class) || !class_exists(JsonType::class)) {
            self::markTestSkipped('web-auth/webauthn-symfony-bundle and doctrine/dbal are not installed (the harness installs them).');
        }
    }
}
