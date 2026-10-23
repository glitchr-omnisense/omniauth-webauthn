<?php

namespace Omniauth\WebAuthn;

use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\TrustPathDenormalizer;
use Webauthn\TrustPath\TrustPath;

/**
 * A passkey as omnibase's userPasskey table holds it: the 13 fields of
 * WebAuthn's credential record (webauthn-lib's Webauthn\CredentialRecord),
 * under the same names, in the values of the columns - the credential id and
 * the public key in standard base64 with its padding (the text of the
 * bundle's `base64` type and of omnibase's `passkey_base64`), the AAGUID as
 * its text, the trust path as the array webauthn-lib normalizes it to
 * (`[]`, or `['x5c' => [...]]`). A row written by
 * web-auth/webauthn-symfony-bundle is a record here (fromRow()), and a record
 * made here is a row the bundle reads (toRow()); toCredentialRecord() and
 * fromCredentialRecord() do what omnibase's PasskeyRepository does.
 *
 * Immutable: after a sign-in, Passkeys::used() receives the record with its
 * counter and backup flags moved (after()).
 */
final readonly class PasskeyRecord
{
    /** The AAGUID of an authenticator that names no model (attestation "none"). */
    public const NO_AAGUID = '00000000-0000-0000-0000-000000000000';

    /**
     * @param list<string>              $transports how the browser reaches the authenticator ("internal", "usb", "hybrid"...)
     * @param array<string, mixed>      $trustPath  [] for none, ['x5c' => [...]] for a chain of certificates
     * @param array<string, mixed>|null $otherUI
     */
    public function __construct(
        /** The credential's id: base64 of its bytes, as the column keeps it. */
        public string $publicKeyCredentialId,
        public string $type = 'public-key',
        public array $transports = [],
        public string $attestationType = 'none',
        public array $trustPath = [],
        public string $aaguid = self::NO_AAGUID,
        /** The public key: base64 of its COSE bytes. */
        public string $credentialPublicKey = '',
        /** The account's handle (Accounts::handle(), its id as text). */
        public string $userHandle = '',
        /** The signature counter the authenticator last gave. */
        public int $counter = 0,
        public ?array $otherUI = null,
        public ?bool $backupEligible = null,
        public ?bool $backupStatus = null,
        public ?bool $uvInitialized = null,
    ) {
    }

    /** The credential id's bytes. */
    public function credentialId(): string
    {
        return self::bytes($this->publicKeyCredentialId);
    }

    /** The public key's COSE bytes. */
    public function publicKey(): string
    {
        return self::bytes($this->credentialPublicKey);
    }

    /** webauthn-lib's record of this passkey: what a ceremony is checked against (omnibase's PasskeyRepository::credentialRecord()). */
    public function toCredentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            $this->credentialId(),
            $this->type,
            $this->transports,
            $this->attestationType,
            (new TrustPathDenormalizer())->denormalize($this->trustPath, TrustPath::class),
            Uuid::fromString($this->aaguid),
            $this->publicKey(),
            $this->userHandle,
            $this->counter,
            $this->otherUI,
            $this->backupEligible,
            $this->backupStatus,
            $this->uvInitialized,
        );
    }

    /** The record of what webauthn-lib made or moved (omnibase's PasskeyRepository::fill()). */
    public static function fromCredentialRecord(CredentialRecord $record): self
    {
        return new self(
            base64_encode($record->publicKeyCredentialId),
            $record->type,
            array_values($record->transports),
            $record->attestationType,
            (new TrustPathDenormalizer())->normalize($record->trustPath),
            $record->aaguid->toRfc4122(),
            base64_encode($record->credentialPublicKey),
            $record->userHandle,
            $record->counter,
            $record->otherUI,
            $record->backupEligible,
            $record->backupStatus,
            $record->uvInitialized,
        );
    }

    /** This passkey after a sign-in webauthn-lib checked: its counter and its flags as the assertion left them. */
    public function after(CredentialRecord $checked): self
    {
        return new self(
            $this->publicKeyCredentialId,
            $this->type,
            $this->transports,
            $this->attestationType,
            $this->trustPath,
            $this->aaguid,
            $this->credentialPublicKey,
            $this->userHandle,
            $checked->counter,
            $this->otherUI,
            $checked->backupEligible,
            $checked->backupStatus,
            $checked->uvInitialized,
        );
    }

    /**
     * A row of the userPasskey table, as the database gives it back: the
     * JSON columns as their text (or decoded), the booleans as 0/1 or bools,
     * the counter as a number or its text. Other columns (id, user_id, label,
     * dates) are ignored.
     *
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        $json = static fn (mixed $value): mixed => \is_string($value) ? json_decode($value, true, 512, \JSON_THROW_ON_ERROR) : $value;
        $bool = static fn (mixed $value): ?bool => null === $value ? null : (bool) $value;

        return new self(
            (string) $row['publicKeyCredentialId'],
            (string) ($row['type'] ?? 'public-key'),
            array_values((array) ($json($row['transports'] ?? []) ?? [])),
            (string) ($row['attestationType'] ?? 'none'),
            (array) ($json($row['trustPath'] ?? []) ?? []),
            (string) ($row['aaguid'] ?? self::NO_AAGUID),
            (string) $row['credentialPublicKey'],
            (string) $row['userHandle'],
            (int) ($row['counter'] ?? 0),
            $json($row['otherUI'] ?? null),
            $bool($row['backupEligible'] ?? null),
            $bool($row['backupStatus'] ?? null),
            $bool($row['uvInitialized'] ?? null),
        );
    }

    /**
     * The 13 columns as the bundle's DBAL types (and omnibase's) write them:
     * base64 text, the JSON columns encoded as Doctrine's JSON type encodes
     * them, the booleans as 0/1 (or null), the counter as a number.
     *
     * @return array<string, string|int|null>
     */
    public function toRow(): array
    {
        $json = static fn (mixed $value): string => json_encode($value, \JSON_THROW_ON_ERROR | \JSON_PRESERVE_ZERO_FRACTION);
        $bool = static fn (?bool $value): ?int => null === $value ? null : (int) $value;

        return [
            'publicKeyCredentialId' => $this->publicKeyCredentialId,
            'type' => $this->type,
            'transports' => $json($this->transports),
            'attestationType' => $this->attestationType,
            'trustPath' => $json($this->trustPath),
            'aaguid' => $this->aaguid,
            'credentialPublicKey' => $this->credentialPublicKey,
            'userHandle' => $this->userHandle,
            'counter' => $this->counter,
            'otherUI' => null === $this->otherUI ? null : $json($this->otherUI),
            'backupEligible' => $bool($this->backupEligible),
            'backupStatus' => $bool($this->backupStatus),
            'uvInitialized' => $bool($this->uvInitialized),
        ];
    }

    private static function bytes(string $base64): string
    {
        $bytes = base64_decode($base64, true);
        if (false === $bytes) {
            throw new \UnexpectedValueException('A passkey keeps its credential id and its public key in base64.');
        }

        return $bytes;
    }
}
