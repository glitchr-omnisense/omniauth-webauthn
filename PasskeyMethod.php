<?php

namespace Omniauth\WebAuthn;

use Omniauth\Attempt;
use Omniauth\Context;
use Omniauth\Contract\Accounts;
use Omniauth\Enrolled;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Method\Challenge;
use Omniauth\Method\Challenging;
use Omniauth\Method\Enrolling;
use Omniauth\Method\Verdict;
use Omniauth\Proof;
use Omniauth\WebAuthn\Contract\Passkeys;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Passkeys (WebAuthn) over web-auth/webauthn-lib, framework-free: a first
 * factor, after which no second one is asked (Marco's decision QA1: it proves
 * the device and the gesture or the code that unlocks it - user verification
 * is required at every ceremony).
 *
 * Signing in: begin() gives the request options (a 32-byte challenge, the
 * relying party's id, user verification required, no list of credentials: a
 * discoverable passkey, the person picks it), as the JSON webauthn-lib's
 * serializer writes - the JSON assets/security/webauthn.js parses today with
 * PublicKeyCredential.parseRequestOptionsFromJSON(); verify() takes what the
 * browser's credential.toJSON() posts (['json' => ...], or its keys as the
 * proof), finds the passkey by its id, has webauthn-lib check the assertion
 * (challenge, origin, relying party, presence and verification, signature,
 * counter, backup flags) and saves the counter and the flags
 * (Passkeys::used()).
 *
 * Registering, from the settings: enrolBegin() gives the creation options for
 * the account (its handle as the user's id, its identifier and display name,
 * its passkeys excluded); enrolConfirm() has webauthn-lib check the
 * attestation and adds the record (['label' => ...] names it).
 *
 * What a ceremony remembers between its two steps (the challenge, the
 * relying party's id) stays in the attempt, never in the answer; a challenge
 * serves once.
 */
final class PasskeyMethod implements Challenging, Enrolling
{
    public const CHALLENGE_LENGTH = 32;
    /** What webauthn-lib checks by default: ES256, RS256. */
    public const ALGORITHMS = [-7, -257];

    private readonly SerializerInterface $serializer;
    private readonly AttestationStatementSupportManager $attestations;

    /** @param int|null $timeout milliseconds the browser gives the person, null for its own */
    public function __construct(
        private readonly Accounts $accounts,
        private readonly Passkeys $passkeys,
        private readonly RelyingParty $rp = new RelyingParty(),
        private readonly ?int $timeout = null,
    ) {
        // Attestation "none" asked, "none" accepted: what web-auth/webauthn-symfony-bundle does without metadata.
        $this->attestations = new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]);
        $this->serializer = (new WebauthnSerializerFactory($this->attestations))->create();
    }

    public function factor(): Factor
    {
        return Factor::Passkey;
    }

    public function begin(Attempt $attempt, Proof $proof, Context $context): Challenge
    {
        if (!$this->rp->serves($context)) {
            return Challenge::failed(Failure::Refused, 'relying-party');
        }
        $challenge = random_bytes(self::CHALLENGE_LENGTH);
        $rpId = $this->rp->id($context);
        $attempt->keep(Factor::Passkey, ['challenge' => base64_encode($challenge), 'rp' => $rpId]);

        return Challenge::json($this->json(self::requestOptions($challenge, $rpId, $this->timeout)));
    }

    public function verify(Attempt $attempt, Proof $proof, Context $context): Verdict
    {
        $kept = $attempt->take(Factor::Passkey);
        if (!\is_array($kept) || !\is_string($kept['challenge'] ?? null) || !\is_string($kept['rp'] ?? null)) {
            return Verdict::expired();
        }
        $response = $this->response($proof, AuthenticatorAssertionResponse::class, $credential);
        if (null === $response) {
            return Verdict::refused(Failure::BadCredentials, 'unreadable-credential');
        }
        $record = $this->passkeys->byCredentialId(base64_encode($credential->rawId));
        if (null === $record) {
            return Verdict::refused(Failure::BadCredentials, 'unknown-passkey');
        }
        $options = self::requestOptions((string) base64_decode($kept['challenge']), $kept['rp'], $this->timeout);
        try {
            $checked = AuthenticatorAssertionResponseValidator::create($this->ceremonies($context)->requestCeremony())
                ->check($record->toCredentialRecord(), $response, $options, $this->host($context), null);
        } catch (\Throwable) {
            // webauthn-lib's reason (a challenge, an origin, a signature, a counter gone back) is the server's log, not the page's.
            return Verdict::refused(Failure::BadCredentials, 'invalid-assertion');
        }
        $account = $this->accounts->byHandle($record->userHandle);
        if (null === $account) {
            return Verdict::refused(Failure::BadCredentials, 'unknown-passkey');
        }
        $this->passkeys->used($record->after($checked));

        return Verdict::passed($account);
    }

    public function enrolBegin(Attempt $enrolment, Proof $proof, Context $context): Challenge
    {
        $account = $enrolment->account() ?? throw new \LogicException('An enrolment has its account.');
        if (!$this->rp->serves($context)) {
            return Challenge::failed(Failure::Refused, 'relying-party');
        }
        $challenge = random_bytes(self::CHALLENGE_LENGTH);
        $rpId = $this->rp->id($context);
        $enrolment->keep(Factor::Passkey, ['challenge' => base64_encode($challenge), 'rp' => $rpId, 'name' => $this->rp->name($context)]);

        return Challenge::json($this->json($this->creationOptions($account, $challenge, $rpId, $this->rp->name($context), true)));
    }

    public function enrolConfirm(Attempt $enrolment, Proof $proof, Context $context): Enrolled
    {
        $account = $enrolment->account() ?? throw new \LogicException('An enrolment has its account.');
        $kept = $enrolment->take(Factor::Passkey);
        if (!\is_array($kept) || !\is_string($kept['challenge'] ?? null) || !\is_string($kept['rp'] ?? null)) {
            return Enrolled::failed(Failure::Expired);
        }
        $response = $this->response($proof, AuthenticatorAttestationResponse::class, $credential);
        if (null === $response) {
            return Enrolled::failed(Failure::BadCredentials, 'unreadable-credential');
        }
        $options = $this->creationOptions($account, (string) base64_decode($kept['challenge']), $kept['rp'], (string) ($kept['name'] ?? $kept['rp']), false);
        try {
            $made = AuthenticatorAttestationResponseValidator::create($this->ceremonies($context)->creationCeremony())
                ->check($response, $options, $this->host($context));
        } catch (\Throwable) {
            return Enrolled::failed(Failure::BadCredentials, 'invalid-attestation');
        }
        $record = PasskeyRecord::fromCredentialRecord($made);
        if (null !== $this->passkeys->byCredentialId($record->publicKeyCredentialId)) {
            return Enrolled::failed(Failure::BadCredentials, 'known-passkey');
        }
        $label = trim($proof->string('label'));
        $this->passkeys->add($account, $record, '' !== $label ? mb_substr($label, 0, 100) : null);

        return Enrolled::done();
    }

    /** The serializer webauthn-lib reads and writes its JSON with (the host may parse a posted credential with it). */
    public function serializer(): SerializerInterface
    {
        return $this->serializer;
    }

    private static function requestOptions(string $challenge, string $rpId, ?int $timeout): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            $challenge,
            rpId: $rpId,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: $timeout,
        );
    }

    /** @param bool $exclude list the account's passkeys, so that one authenticator is not registered twice */
    private function creationOptions(object $account, string $challenge, string $rpId, string $name, bool $exclude): PublicKeyCredentialCreationOptions
    {
        $excluded = [];
        if ($exclude) {
            foreach ($this->passkeys->of($account) as $record) {
                $excluded[] = PublicKeyCredentialDescriptor::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $record->credentialId(), $record->transports);
            }
        }

        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($name, $rpId),
            PublicKeyCredentialUserEntity::create($this->accounts->identifier($account), $this->accounts->handle($account), $this->accounts->displayName($account)),
            $challenge,
            array_map(static fn (int $alg) => PublicKeyCredentialParameters::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $alg), self::ALGORITHMS),
            // A passkey is discoverable (the sign-in names no account) and verified.
            AuthenticatorSelectionCriteria::create(null, AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED, AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $excluded,
            $this->timeout,
        );
    }

    /**
     * The browser's credential, and its response if it is of the class a step expects.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T|null
     */
    private function response(Proof $proof, string $class, ?PublicKeyCredential &$credential = null): ?object
    {
        try {
            $json = $proof->json();
            // What webauthn-lib's denormalizer reads without asking: a credential of the browser's shape.
            $shape = json_decode($json, true, 16, \JSON_THROW_ON_ERROR);
            if (!\is_array($shape) || !\is_string($shape['id'] ?? null) || !\is_string($shape['rawId'] ?? null) || !\is_string($shape['type'] ?? null) || !\is_array($shape['response'] ?? null)) {
                return null;
            }
            $credential = $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
        } catch (\Throwable) {
            return null;
        }

        return $credential instanceof PublicKeyCredential && $credential->response instanceof $class ? $credential->response : null;
    }

    private function ceremonies(Context $context): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAttestationStatementSupportManager($this->attestations);
        $factory->setAllowedOrigins($this->rp->origins($context));
        $factory->setSecuredRelyingPartyId($this->rp->insecure);

        return $factory;
    }

    private function host(Context $context): string
    {
        return strtolower(preg_replace('~:\d+$~', '', $context->host) ?? $context->host);
    }

    private function json(object $options): string
    {
        return $this->serializer->serialize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
    }
}
