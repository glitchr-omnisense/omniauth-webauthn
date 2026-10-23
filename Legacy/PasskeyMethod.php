<?php

namespace Omniauth\Passkey;

/*
 * Omniauth\Passkey\PasskeyMethod is now Omniauth\WebAuthn\PasskeyMethod: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\PasskeyMethod (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\PasskeyMethod is deprecated: use Omniauth\WebAuthn\PasskeyMethod (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\PasskeyMethod::class, PasskeyMethod::class);
