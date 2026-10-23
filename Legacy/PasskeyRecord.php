<?php

namespace Omniauth\Passkey;

/*
 * Omniauth\Passkey\PasskeyRecord is now Omniauth\WebAuthn\PasskeyRecord: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\PasskeyRecord (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\PasskeyRecord is deprecated: use Omniauth\WebAuthn\PasskeyRecord (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\PasskeyRecord::class, PasskeyRecord::class);
