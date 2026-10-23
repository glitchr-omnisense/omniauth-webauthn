<?php

namespace Omniauth\Passkey\Contract;

/*
 * Omniauth\Passkey\Contract\Passkeys is now Omniauth\WebAuthn\Contract\Passkeys: omniauth/passkey was renamed
 * omniauth/webauthn (it implements WebAuthn; passkeys are one use of it), which replaces it.
 * The former name is an alias of the new class for one release.
 *
 * @deprecated use Omniauth\WebAuthn\Contract\Passkeys (composer require omniauth/webauthn)
 */
@trigger_error('Omniauth\Passkey\Contract\Passkeys is deprecated: use Omniauth\WebAuthn\Contract\Passkeys (omniauth/webauthn).', \E_USER_DEPRECATED);
class_alias(\Omniauth\WebAuthn\Contract\Passkeys::class, Passkeys::class);
