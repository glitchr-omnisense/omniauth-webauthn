<?php

namespace Omniauth\Passkey\Testing;

use Omniauth\Contract\Accounts;
use Omniauth\Passkey\Contract\Passkeys;
use Omniauth\Passkey\PasskeyRecord;

/** The passkeys in memory, by credential id: tests, the harness's bare script, a first try in plain PHP. */
final class InMemoryPasskeys implements Passkeys
{
    /** @var array<string, PasskeyRecord> */
    public array $records = [];
    /** @var array<string, string|null> */
    public array $labels = [];
    /** @var array<string, int> how many times each was used */
    public array $uses = [];

    public function __construct(private readonly Accounts $accounts)
    {
    }

    public function of(object $account): iterable
    {
        $handle = $this->accounts->handle($account);

        return array_values(array_filter($this->records, static fn (PasskeyRecord $record) => $record->userHandle === $handle));
    }

    public function byCredentialId(string $credentialId): ?PasskeyRecord
    {
        return $this->records[$credentialId] ?? null;
    }

    public function add(object $account, PasskeyRecord $record, ?string $label = null): void
    {
        if ($record->userHandle !== $this->accounts->handle($account)) {
            throw new \LogicException('A passkey is added to the account its user handle names.');
        }
        $this->records[$record->publicKeyCredentialId] = $record;
        $this->labels[$record->publicKeyCredentialId] = $label;
    }

    public function used(PasskeyRecord $record): void
    {
        $this->records[$record->publicKeyCredentialId] = $record;
        $this->uses[$record->publicKeyCredentialId] = ($this->uses[$record->publicKeyCredentialId] ?? 0) + 1;
    }
}
