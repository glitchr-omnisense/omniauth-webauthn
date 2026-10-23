<?php

namespace Omniauth\Passkey\Testing;

/*
 * Omniauth\Passkey\Testing\InMemoryPasskeys is now Omniauth\WebAuthn\Testing\InMemoryPasskeys: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\Testing\InMemoryPasskeys (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\Testing\InMemoryPasskeys is deprecated: use Omniauth\WebAuthn\Testing\InMemoryPasskeys (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\Testing\InMemoryPasskeys::class, InMemoryPasskeys::class);
