---
title: The records and the bundle
order: 35
---

# The records and web-auth/webauthn-symfony-bundle

A `PasskeyRecord` is a passkey as omnibase's `userPasskey` table holds it: the 13 fields of
webauthn-lib's `CredentialRecord`, under the same names, in the values of the columns.

| Field | Column's text | In the record |
|---|---|---|
| `publicKeyCredentialId` | base64 (standard, padded) of the id's bytes | the same base64; `credentialId()` gives the bytes |
| `type` | `public-key` | the same |
| `transports` | JSON, `["internal"]` | a list |
| `attestationType` | `none` | the same |
| `trustPath` | JSON, `[]` or `{"x5c":[...]}` | the array webauthn-lib normalizes it to |
| `aaguid` | a UUID's text | the same |
| `credentialPublicKey` | base64 of the COSE key | the same base64; `publicKey()` gives the bytes |
| `userHandle` | the account's id, as text | the same |
| `counter` | a number | an int |
| `otherUI` | JSON or null | an array or null |
| `backupEligible`, `backupStatus`, `uvInitialized` | 0/1 or null | bools or null |

That text is what the bundle's DBAL types (`base64`, `aaguid`, `trust_path`, `json`) write, and
what omnibase's own (`passkey_base64`, `passkey_aaguid`, `passkey_trust_path`, step AU1) reproduce:

```php
$record = PasskeyRecord::fromRow($row);          // a row as the database gives it back (other columns ignored)
$row = $record->toRow();                         // the 13 columns as the bundle writes them
$credential = $record->toCredentialRecord();     // webauthn-lib's object, as omnibase's PasskeyRepository::credentialRecord() makes it
$record = PasskeyRecord::fromCredentialRecord($credential);   // as PasskeyRepository::fill() copies it
```

An application on Doctrine (omnibase) maps its entity's fields instead: the entity holds the bytes
(its `passkey_base64` type decodes them), so its store gives `base64_encode()` of them.

## Both ways

So that the switch from the bundle (lesringostars at step AU7, then every site) loses no passkey,
`Tests/BundleCompatibilityTest` checks:

1. **registered by the bundle, signed in here**: the row lesringostars' sign-in suite saw the bundle
   write when a passkey was added from the settings (AU1), recorded as it is; and live, the row the
   bundle's DBAL types write for the record webauthn-lib's attestation check makes - the same row;
2. **registered here, read by the bundle**: the row `PasskeyMethod` made, read through the bundle's
   DBAL types into the `CredentialRecord` its repository hands its authenticator, then a sign-in
   checked by webauthn-lib as the bundle configures it; what the bundle saves back equals what
   omniauth writes after the same sign-in.

One difference stays visible: the bundle asked `userVerification: "preferred"` (its default), this
method asks `"required"` at both ceremonies. A passkey registered by the bundle without verification
(`uvInitialized` false) signs in here only if the authenticator verifies the person this time.
