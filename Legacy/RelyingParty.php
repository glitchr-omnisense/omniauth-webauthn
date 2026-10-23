<?php

namespace Omniauth\Passkey;

/*
 * Omniauth\Passkey\RelyingParty is now Omniauth\WebAuthn\RelyingParty: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\RelyingParty (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\RelyingParty is deprecated: use Omniauth\WebAuthn\RelyingParty (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\RelyingParty::class, RelyingParty::class);
