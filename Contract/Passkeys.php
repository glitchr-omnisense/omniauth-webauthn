<?php

namespace Omniauth\Passkey\Contract;

use Omniauth\Passkey\PasskeyRecord;

/**
 * The passkeys of the application's accounts (omnibase: the userPasskey
 * table, Base\Entity\User\Passkey), as PasskeyRecord values.
 */
interface Passkeys
{
    /** @return iterable<PasskeyRecord> the account's passkeys (a registration excludes them) */
    public function of(object $account): iterable;

    /** @param string $credentialId the credential's id in base64, as the table keeps it */
    public function byCredentialId(string $credentialId): ?PasskeyRecord;

    /** A passkey registered for the account, under the name the person gave it (if any). */
    public function add(object $account, PasskeyRecord $record, ?string $label = null): void;

    /** After a sign-in: the counter and the backup flags as the assertion left them (and the host's last-used date). */
    public function used(PasskeyRecord $record): void;
}
