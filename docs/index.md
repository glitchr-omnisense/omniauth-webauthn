# omniauth/webauthn

Passkeys (WebAuthn) as a first factor of [omniscient/omniauth](https://github.com/glitchr-studio/omniauth),
under any PHP host, over web-auth/webauthn-lib 5: the request and creation options a page's script
hands the browser, and the assertion and attestation the browser posts back, checked by
webauthn-lib with nothing turned off. User verification is required at every ceremony, so no second
factor follows a passkey (Marco's decision QA1). The records are those of
web-auth/webauthn-symfony-bundle, both ways: a passkey the bundle registered signs in here, and one
registered here is read by the bundle. It calls no service: the ceremonies happen between the
server, the browser and the authenticator.

```php
new PasskeyMethod($accounts, $passkeys, new RelyingParty(id: 'example.org'));
```

This package was **omniauth/passkey** until 2026-10-23 (renamed: it implements WebAuthn, passkeys
are one use of it). It `replace`s omniauth/passkey, and the former namespace `Omniauth\Passkey\`
stays an alias of `Omniauth\WebAuthn\` for one release (`Legacy/`, each with a deprecation notice).
The factor keeps its name, `passkey` (`Factor::Passkey`).

## Installation

```sh
composer require omniscient/omniauth omniauth/webauthn
```

Requires PHP 8.2 with `ext-openssl`, `omniscient/omniauth` (1.x), `web-auth/webauthn-lib` (^5.3),
`symfony/serializer` and `symfony/uid` (6.4, 7 or 8: standalone components, webauthn-lib's own
ground). No framework. Under omnibridge/symfony and omnibridge/laravel the `passkey` key turns it on
([Hosts](#hosts)).

## Options

`new PasskeyMethod(...)`:

| Argument | Type | Default | |
|---|---|---|---|
| `accounts` | `Omniauth\Contract\Accounts` | required | the handle (the credential's user id), identifier and display name |
| `passkeys` | `Contract\Passkeys` | required | the passkeys, as `PasskeyRecord` values (omnibase: `userPasskey`) |
| `rp` | `RelyingParty` | `new RelyingParty()` | who the passkeys belong to |
| `timeout` | `?int` | `null` | milliseconds the browser gives the person; null: the browser's own |

`new RelyingParty(...)`, read-only:

| Argument | Type | Default | |
|---|---|---|---|
| `id` | `?string` | `null`: each request's host, lower case, without its port | the registrable domain the passkeys belong to (`RELYING_PARTY_ID`); a passkey made for it serves every host under it |
| `name` | `?string` | `null`: the id | what some authenticators show |
| `origins` | `list<string>` | `[]`: the request's own origin | the origins a ceremony may come from (a site and its twin) |
| `insecure` | `list<string>` | `['localhost']` | the ids allowed over plain HTTP (WebAuthn's own exception) |

`serves($context)` is true when the request's host is the id or under it; a host it does not serve
is refused before any challenge (`refused`, reason `relying-party`). Constants:
`PasskeyMethod::CHALLENGE_LENGTH` (32 bytes), `PasskeyMethod::ALGORITHMS` (`[-7, -257]`: ES256,
RS256).

## Capabilities

| | |
|---|---|
| a first factor, `begin()` then `verify()` (`Method\Challenging`) | yes: the request options (no credential listed: a discoverable passkey, the person picks it), then the assertion |
| set up from the settings (`Method\Enrolling`) | yes: the creation options (the account's passkeys excluded), then the attestation, with a label |
| turned off through `revoke()` (`Method\Revocable`) | no: removing a passkey is the store's (the settings page's) |
| a second factor after it | no (QA1): `EnrolledSecondFactors::AFTER` leaves `passkey` out |
| attestation formats | `none` only, asked and accepted (what the bundle does without metadata) |
| algorithms | ES256, RS256 |
| user verification | required at both ceremonies |
| the bundle's rows read and written | yes ([The records and the bundle](records.md)) |

`serializer()` gives the Symfony serializer webauthn-lib reads and writes its JSON with.

## What a ceremony checks

webauthn-lib does the checking; `PasskeyMethod` asks it for everything and turns nothing off:

- **one challenge per ceremony** (32 random bytes), kept in the attempt (never in the answer) and
  taken at the verification: an assertion posted twice finds nothing to check against (`expired`);
- **the origin** among those allowed (the request's own unless `RelyingParty::$origins` names
  them), **the relying party's id** hashed in the authenticator data, the client data's type;
- **user verification required** at the sign-in and at the registration;
- **the signature** with the public key kept; **the counter**: one that goes back (a cloned
  authenticator) is refused; **the backup flags**, consistent, and saved after each sign-in with the
  counter (`Passkeys::used()`);
- at a registration: ES256 or RS256, a discoverable credential (`residentKey: required`), the
  account's passkeys excluded, a credential already known refused.

## Hosts

| | omnibridge/symfony (`omniauth.yaml`) | omnibridge/laravel (`config/omniauth.php`) |
|---|---|---|
| on | `passkey: ~` | `'passkey' => [...]` |
| the relying party | `passkey.rp_id`, `rp_name`, `origins` | the same keys |
| `timeout` | `passkey.timeout` | the same |
| the remember-me after a passkey | `passkey.remember` (`true`; the posted JSON's `remember` wins) | the same |
| the request options | POST `passkey.options_path` (`/login/passkey/options`), route `passkey_login_options` | the same |
| the assertion | POST `passkey.path` (`/login/passkey`), route `passkey_login` | the same |
| the store | `stores.passkeys` (`Omniauth\WebAuthn\Contract\Passkeys`) | `stores.passkeys`, or omnibase's `Base\Auth\UserPasskeys` |

Both answer in the JSON web-auth/webauthn-symfony-bundle answered, so a page's script stays as it
is: the options as `{"status": "ok", "errorMessage": "", ...the options}`, a sign-in as
`{"status": "ok", "errorMessage": ""}` (with `redirect` when a second factor follows), a refused sign-in as
`{"status": "failed", "errorMessage": ...}` with HTTP 401, options that could not be given with
HTTP 400. Registering a passkey from the settings
is the application's page (omnibase's), through `$omniauth->enrol(Factor::Passkey, $account)`.

## Errors

The failures and their reasons are listed in [The method](webauthn.md#refusals): `expired`,
`bad-credentials` (`unreadable-credential`, `unknown-passkey`, `invalid-assertion`,
`invalid-attestation`, `known-passkey`), `refused` (`relying-party`). webauthn-lib's own message
is never shown. The exceptions:

| Exception | When |
|---|---|
| `\UnexpectedValueException` | a `PasskeyRecord` whose credential id or public key is not base64 (a store's mistake) |
| `\JsonException` | `PasskeyRecord::fromRow()` of a JSON column that is not JSON |
| `\InvalidArgumentException`, `\LogicException` | the test doubles: a `SoftwareAuthenticator` key that is not P-256; `InMemoryPasskeys::add()` of a record for another account |

## Verified, and not

Run in omniauth's harness on 2026-10-25 (PHP 8.4, doctrine/dbal 4 and
web-auth/webauthn-symfony-bundle 5.3 installed beside): omniauth/webauthn's 34 tests green. They
cover a registration from the settings then a sign-in through the conductor, by the software
authenticator, and no second factor after it (QA1); the options' JSON; every refusal (a forged
signature, an unknown passkey, a challenge used twice, another challenge, another origin, another
relying party, a host the relying party does not serve, a person not verified, a counter gone back,
the same authenticator registered twice, an unreadable credential); the backup flags saved; one
relying party for two hosts (QA9), and `localhost` over HTTP; **both ways with the bundle**
(`Tests/BundleCompatibilityTest`: a row the bundle wrote signs in here, a row written here is read
and verified by the bundle as it configures webauthn-lib); `docs/installation.md` run as written;
in plain PHP (`BareTest`), nothing loaded but omniauth, webauthn-lib and what it requires.

Not verified: a real browser and a real authenticator (Chrome's virtual authenticator, at steps AU7
and AU8 of the omniauth plan); attestation formats other than `none` and metadata statements (not
asked); a host's store and the bridges' answers around the JSON, tested in their own suites.
