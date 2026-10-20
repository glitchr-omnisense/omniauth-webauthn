<?php

namespace Omniauth\Passkey\Testing;

/**
 * A passkey authenticator in PHP, for tests (the one lesringostars' sign-in
 * characterisation used, plan "omniauth" AU0): a P-256 key made by OpenSSL,
 * which answers the options a site gives with the JSON a browser's
 * PublicKeyCredential.toJSON() posts - attestation "none" at a registration,
 * an ES256 signature at a sign-in. The person is present and verified (the
 * flags UP and UV) unless told otherwise; nothing is backed up unless told.
 *
 * No library: its CBOR is the little WebAuthn needs. A host's tests sign in
 * with it under Symfony and Laravel alike, with no browser.
 */
final class SoftwareAuthenticator
{
    private const FLAG_UP = 0x01;
    private const FLAG_UV = 0x04;
    private const FLAG_BE = 0x08;
    private const FLAG_BS = 0x10;
    private const FLAG_AT = 0x40;

    private \OpenSSLAsymmetricKey $key;
    public readonly string $credentialId;
    private ?string $userHandle = null;

    /**
     * @param string      $origin      the page's origin, as the browser writes it in the client data (https://example.org)
     * @param string|null $privateKey  a PEM P-256 key, to be the same authenticator from one run to another; a new key otherwise
     * @param string|null $credentialId the credential's bytes; 32 random bytes otherwise
     */
    public function __construct(
        private readonly string $origin,
        ?string $privateKey = null,
        ?string $credentialId = null,
        public int $counter = 0,
        public bool $verified = true,
        public bool $backupEligible = false,
        public bool $backedUp = false,
    ) {
        $key = null !== $privateKey ? openssl_pkey_get_private($privateKey) : openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => \OPENSSL_KEYTYPE_EC]);
        if (!$key instanceof \OpenSSLAsymmetricKey || 'prime256v1' !== (openssl_pkey_get_details($key)['ec']['curve_name'] ?? null)) {
            throw new \InvalidArgumentException('A software authenticator holds a P-256 key.');
        }
        $this->key = $key;
        $this->credentialId = $credentialId ?? random_bytes(32);
    }

    /**
     * navigator.credentials.create() on the creation options (their JSON, or decoded).
     *
     * @param string|array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    public function create(string|array $options): array
    {
        $options = self::options($options);
        $this->userHandle = self::decode($options['user']['id']);
        $clientData = $this->clientData('webauthn.create', $options['challenge']);
        $authenticatorData = $this->authenticatorData($options['rp']['id'] ?? (string) parse_url($this->origin, \PHP_URL_HOST), self::FLAG_AT)
            .str_repeat("\0", 16)                       // aaguid: none named
            .pack('n', \strlen($this->credentialId)).$this->credentialId
            .$this->publicKey();
        $attestationObject = self::cbor(['fmt' => 'none', 'attStmt' => [], 'authData' => self::bytes($authenticatorData)]);

        return [
            'id' => self::encode($this->credentialId),
            'rawId' => self::encode($this->credentialId),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'response' => [
                'clientDataJSON' => self::encode($clientData),
                'attestationObject' => self::encode($attestationObject),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => new \stdClass(),
        ];
    }

    /**
     * navigator.credentials.get() on the request options (their JSON, or decoded).
     *
     * @param string|array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    public function get(string|array $options): array
    {
        $options = self::options($options);
        $clientData = $this->clientData('webauthn.get', $options['challenge']);
        $authenticatorData = $this->authenticatorData($options['rpId'] ?? (string) parse_url($this->origin, \PHP_URL_HOST), 0);
        openssl_sign($authenticatorData.hash('sha256', $clientData, true), $signature, $this->key, \OPENSSL_ALGO_SHA256);

        return [
            'id' => self::encode($this->credentialId),
            'rawId' => self::encode($this->credentialId),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'response' => [
                'clientDataJSON' => self::encode($clientData),
                'authenticatorData' => self::encode($authenticatorData),
                'signature' => self::encode($signature),
                'userHandle' => null === $this->userHandle ? null : self::encode($this->userHandle),
            ],
            'clientExtensionResults' => new \stdClass(),
        ];
    }

    /** The credential's public key, COSE (RFC 9053: EC2, ES256, P-256), as a credential record keeps it. */
    public function publicKey(): string
    {
        $ec = openssl_pkey_get_details($this->key)['ec'];

        return self::cbor([1 => 2, 3 => -7, -1 => 1, -2 => self::bytes(str_pad($ec['x'], 32, "\0", \STR_PAD_LEFT)), -3 => self::bytes(str_pad($ec['y'], 32, "\0", \STR_PAD_LEFT))]);
    }

    /** The private key, PEM: to be this authenticator again later (new self($origin, $authenticator->privateKey(), $authenticator->credentialId)). */
    public function privateKey(): string
    {
        openssl_pkey_export($this->key, $pem);

        return $pem;
    }

    /** The account this authenticator's credential belongs to (what create() learns from the options): the userHandle it sends. */
    public function belongsTo(string $userHandle): self
    {
        $this->userHandle = $userHandle;

        return $this;
    }

    /** @param string|array<string, mixed> $options */
    private static function options(string|array $options): array
    {
        return \is_string($options) ? json_decode($options, true, 512, \JSON_THROW_ON_ERROR) : $options;
    }

    private function clientData(string $type, string $challenge): string
    {
        return json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $this->origin, 'crossOrigin' => false], \JSON_UNESCAPED_SLASHES);
    }

    private function authenticatorData(string $rpId, int $flags): string
    {
        $flags |= self::FLAG_UP;
        $flags |= $this->verified ? self::FLAG_UV : 0;
        $flags |= $this->backupEligible ? self::FLAG_BE : 0;
        $flags |= $this->backedUp ? self::FLAG_BS : 0;

        return hash('sha256', $rpId, true).\chr($flags).pack('N', ++$this->counter);
    }

    /** base64url without padding, as WebAuthn's JSON writes bytes. */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $base64url): string
    {
        return (string) base64_decode(strtr($base64url, '-_', '+/'));
    }

    /** A byte string for cbor(), told apart from a text string. */
    private static function bytes(string $bytes): \ArrayObject
    {
        return new \ArrayObject(['bytes' => $bytes]);
    }

    /** The little of CBOR (RFC 8949) WebAuthn asks for: integers, byte and text strings, maps. */
    private static function cbor(mixed $value): string
    {
        return match (true) {
            $value instanceof \ArrayObject => self::head(2, \strlen($value['bytes'])).$value['bytes'],
            \is_int($value) => $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value),
            \is_string($value) => self::head(3, \strlen($value)).$value,
            \is_array($value) => self::head(5, \count($value)).implode('', array_map(static fn ($key, $item) => self::cbor($key).self::cbor($item), array_keys($value), $value)),
        };
    }

    private static function head(int $major, int $length): string
    {
        return match (true) {
            $length < 24 => \chr($major << 5 | $length),
            $length < 0x100 => \chr($major << 5 | 24).\chr($length),
            $length < 0x10000 => \chr($major << 5 | 25).pack('n', $length),
            default => \chr($major << 5 | 26).pack('N', $length),
        };
    }
}
