# omniauth/webauthn

WebAuthn - passkeys - for [omnisense/omniauth](https://github.com/glitchr-omnisense/omniauth), **under any PHP
host**, over web-auth/webauthn-lib: the sign-in (request options, then the assertion checked) and
the registration from an account's settings (creation options, then the attestation checked), on
the credential record as omnibase's `userPasskey` table holds it - so a passkey registered by
web-auth/webauthn-symfony-bundle signs in here, and one registered here is read by the bundle.

```php
use Omniauth\{ArrayState, Context, Factor, Omniauth};
use Omniauth\Method\Methods;
use Omniauth\WebAuthn\{PasskeyMethod, RelyingParty};

$omniauth = new Omniauth(
    accounts: $accounts,                                   // your accounts, behind Omniauth\Contract\Accounts
    methods: new Methods([
        new PasskeyMethod($accounts, $passkeys, new RelyingParty(id: 'example.org')),   // $passkeys: your table, behind Contract\Passkeys
    ]),
    state: new ArrayState($_SESSION),
);
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: $_SERVER['REMOTE_ADDR']);

$options = $omniauth->begin('passkey', $context);          // $options->payload: the JSON for parseRequestOptionsFromJSON()
// ... the browser signs: navigator.credentials.get(), then credential.toJSON(), posted back
$result = $omniauth->verify('passkey', $context, ['json' => $posted]);
// Authenticated, $result->passed === [Factor::Passkey]: no second factor after a passkey

$enrolment = $omniauth->enrol(Factor::Passkey, $account);  // from the settings
$options = $enrolment->begin($context);                    // the JSON for parseCreationOptionsFromJSON()
$enrolment->confirm($context, ['json' => $posted, 'label' => 'MacBook Touch ID']);
```

It requires omnisense/omniauth and web-auth/webauthn-lib ^5.3 - framework-free, with its CBOR,
COSE and PKI libraries and the standalone Symfony components it is written on (serializer,
property-info, property-access, string, uid, clock). No bundle, no kernel, no container.

## The shape

| | |
|---|---|
| `PasskeyMethod` | a first factor (`Challenging`, `Enrolling`): `begin()`/`verify()` sign in, `enrolBegin()`/`enrolConfirm()` register |
| `PasskeyRecord` | a passkey as the table holds it: the 13 fields of WebAuthn's `CredentialRecord`, same names, the credential id and the public key in base64; `fromRow()`/`toRow()` for the table's text, `toCredentialRecord()`/`fromCredentialRecord()` for webauthn-lib, `after()` once a sign-in moved its counter and flags |
| `Contract\Passkeys` | the store: `of($account)`, `byCredentialId($base64)`, `add($account, $record, $label)`, `used($record)` (omnibase fills it on `userPasskey`, step AU4) |
| `RelyingParty` | the relying party's id (a registrable domain), its name, the origins allowed, the ids allowed over plain http (`localhost`) |
| `Testing\SoftwareAuthenticator` | a P-256 authenticator in PHP that answers the options with the browser's JSON: tests sign in with no browser |
| `Testing\InMemoryPasskeys` | the store in memory |

## What a ceremony checks

webauthn-lib does the checking; `PasskeyMethod` asks it for everything and turns nothing off:

- **one challenge per ceremony** (32 random bytes), kept in the attempt (never in the answer) and
  taken at the verification: an assertion posted twice finds nothing to check against (`expired`);
- **the origin** among those allowed (the request's own unless `RelyingParty::$origins` names
  them), **the relying party's id** hashed in the authenticator data, the client data's type;
- **user verification required** at the sign-in and at the registration - the device and the
  gesture or the code that unlocks it; that is why **no second factor follows a passkey** (Marco's
  decision QA1: `EnrolledSecondFactors::AFTER` leaves it out);
- **the signature** with the public key kept; **the counter**: one that goes back (a cloned
  authenticator) is refused; **the backup flags**, consistent, and saved after each sign-in with the
  counter (`Passkeys::used()`);
- at a registration: attestation `"none"` asked and accepted (what the bundle does without
  metadata), ES256 or RS256, a discoverable credential (`residentKey: required`), the account's
  passkeys excluded, a credential already known refused.

A refusal says `bad-credentials` with a stable reason (`unknown-passkey`, `invalid-assertion`,
`invalid-attestation`, `known-passkey`, `unreadable-credential`); webauthn-lib's own message is for
the server's log, not the page.

## One relying party for two hosts (QA9)

A passkey belongs to a registrable domain. Marco's decision: the Symfony site and its Laravel twin
share one in production - `new RelyingParty(id: 'example.org', origins: ['https://www.example.org',
'https://twin.example.org'])`, and a passkey registered on one host signs in on the other. With no
id, each request's host is the id (the port never enters it: `localhost` serves
`https://localhost:8443` and `http://localhost:8132` alike).

## Compatible both ways with web-auth/webauthn-symfony-bundle

The bundle writes `userPasskey` through its DBAL types (`base64`, `aaguid`, `trust_path`, `json`),
whose text omnibase's own types reproduce since AU1. `PasskeyRecord` keeps that text: `fromRow()`
reads a row the bundle wrote, `toRow()` writes the row the bundle reads. `Tests/BundleCompatibilityTest`
proves it both ways - see "Verified".

## Formerly omniauth/passkey

This package was **omniauth/passkey** until 2026-10-23 (renamed: it implements WebAuthn, and
passkeys are one use of it), with its history. It `replace`s omniauth/passkey, so the two are never
installed together, and the former namespace `Omniauth\Passkey\` stays an alias of
`Omniauth\WebAuthn\` for one release (`Legacy/`: each former name loads the new class, with a
deprecation notice): code written against the former names goes on working until the next release.
The class names (`PasskeyMethod`, `PasskeyRecord`, `Contract\Passkeys`...), the method's name
(`'passkey'`, `Factor::Passkey`), the JSON, the routes a host gives it and the stored records do not
change; the word "passkey" stays what a person reads.

```sh
composer remove omniauth/passkey && composer require omniauth/webauthn
```

## Documentation

- [Overview](docs/index.md): options, capabilities, what a ceremony checks, the hosts' keys, errors
- [Installation, in plain PHP](docs/installation.md)
- [The method](docs/webauthn.md): signing in, registering, refusals
- [The records and the bundle](docs/records.md)

## Verified, and not

- Verified (omniauth's harness, `docker compose run --rm omniauth test` in the core's `docker/`, PHP
  8.4; every file linted on PHP 8.2):
  - a registration from the settings then a sign-in, through the conductor, by the software
    authenticator; no second factor after it for an account a password asks one of (QA1); the
    options' JSON (challenge, `rpId`, `allowCredentials: []`, `userVerification: required`; the
    creation options' relying party, user - the handle as its id, as omnibase's
    `WebauthnUserEntityRepository` gives it -, algorithms, selection, exclusions);
  - every refusal: a forged signature, an unknown passkey, a challenge used twice, another
    challenge, another origin, another relying party, a host the relying party does not serve, a
    person not verified (sign-in and registration), a counter gone back, the same authenticator
    registered twice, an unreadable credential; the backup flags saved; one relying party for two
    hosts (QA9), and `localhost` over http;
  - **a passkey the bundle registered signs in here**: the row lesringostars' sign-in suite saw
    the bundle write at a registration (AU1), recorded as it is, read by `fromRow()` and signed in
    with, its counter written back; and live, the row the bundle's DBAL types (5.3.9, doctrine/dbal
    4, MySQL's platform) write for the record webauthn-lib's attestation check makes, as the bundle's
    creation controller does - the same row, and the same as `fromCredentialRecord()->toRow()`;
  - **a passkey registered here is read and verified by the bundle**: its row through the bundle's
    DBAL types is the `CredentialRecord` its repository hands its authenticator, webauthn-lib's
    assertion check configured as the bundle configures it (no `allowed_origins`, profile "default")
    signs in with it, and what the bundle would save back is the row omniauth writes after the same
    sign-in; a certificate trust path written and read as the bundle does;
  - `docs/installation.md` run as written; in plain PHP (`BareTest`), a registration and a sign-in
    by hand loading nothing but omniauth, webauthn-lib and the libraries it requires - no class of a
    framework, of the bundle, of Doctrine or of an application, though the harness has them.
- Not verified: a real browser and a real authenticator (Chrome's virtual authenticator, at AU7 and
  AU8); attestation formats other than `"none"` and metadata statements (not asked, as today); a
  host's store (`Base\Auth\UserPasskeys`, AU4) and the bridges' answers around the JSON (AU6, AU8);
  a row written by the bundle in a running site after AU1 read by this package in the same database
  (the text is compared, not the database).

## Licence

MIT.
