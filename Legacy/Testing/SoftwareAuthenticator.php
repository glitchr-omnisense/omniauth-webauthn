<?php

namespace Omniauth\Passkey\Testing;

/*
 * Omniauth\Passkey\Testing\SoftwareAuthenticator is now Omniauth\WebAuthn\Testing\SoftwareAuthenticator: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\Testing\SoftwareAuthenticator (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\Testing\SoftwareAuthenticator is deprecated: use Omniauth\WebAuthn\Testing\SoftwareAuthenticator (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\Testing\SoftwareAuthenticator::class, SoftwareAuthenticator::class);
