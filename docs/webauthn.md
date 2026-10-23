---
title: The method
order: 2
---

# The method

```php
new PasskeyMethod(
    accounts: $accounts,                 // Omniauth\Contract\Accounts
    passkeys: $passkeys,                 // Omniauth\WebAuthn\Contract\Passkeys
    rp: new RelyingParty(
        id: 'example.org',               // RELYING_PARTY_ID; null: each request's host
        name: 'Les Ringo Stars',         // what some authenticators show; null: the id
        origins: [],                     // the origins allowed; []: the request's own
        insecure: ['localhost'],         // the ids allowed over plain http
    ),
    timeout: null,                       // milliseconds the browser gives the person; null: its own
);
```

A first factor. No second factor follows it (QA1): user verification is required at every
ceremony.

## Signing in

| Step | Call | Gives | Keeps in the attempt |
|---|---|---|---|
| options | `$omniauth->begin('passkey', $context)` | `Challenge::json()`: `challenge`, `rpId`, `allowCredentials: []`, `userVerification: "required"` | the challenge, the id |
| assertion | `$omniauth->verify('passkey', $context, ['json' => $posted])` | `Result` (`Authenticated`, `passed: [passkey]`) | nothing: the challenge is taken |

The proof is what the browser's `credential.toJSON()` gives, under `json` - or its keys as the
proof itself. The passkey is found by its id (`Passkeys::byCredentialId(base64)`), its account by
its user handle (`Accounts::byHandle()`); after the check, `Passkeys::used()` receives the record
with its counter and backup flags moved.

## Registering, from the settings

| Step | Call | Gives |
|---|---|---|
| options | `$omniauth->enrol(Factor::Passkey, $account)->begin($context)` | `Challenge::json()`: `rp`, `user` (id: the handle, name: the identifier, displayName), `challenge`, `pubKeyCredParams` (ES256, RS256), `authenticatorSelection` (verification and resident key required), `attestation: "none"`, `excludeCredentials` (the account's passkeys) |
| attestation | `->confirm($context, ['json' => $posted, 'label' => '...'])` | `Enrolled`: done, or failed with its reason; the record added by `Passkeys::add($account, $record, $label)` |

## Refusals

| Failure | Reason | When |
|---|---|---|
| `expired` | - | no options begun in this attempt, or already used |
| `bad-credentials` | `unreadable-credential` | the JSON is not a credential of the expected kind |
| | `unknown-passkey` | no passkey of that id, or its account is gone |
| | `invalid-assertion` | webauthn-lib refused: challenge, origin, relying party, presence, verification, signature, counter, backup flags |
| | `invalid-attestation` | webauthn-lib refused the registration |
| | `known-passkey` | this credential is already registered |
| `refused` | `relying-party` | the request's host is not under the relying party's id |

The conductor throttles both steps (`passkey`, `passkey.begin`) like every method.

## What the host does

Send `Challenge::$payload` as it is (the bridges wrap it as web-auth/webauthn-symfony-bundle did,
`status: "ok"`, `errorMessage: ""`, so `assets/security/webauthn.js` stays as it is); post the
browser's JSON back; check the settings page's CSRF token before a registration; on
`Authenticated`, renew the session id.
