---
title: Installation
order: 10
---

# Installation

```sh
composer require omniscient/omniauth omniauth/webauthn
```

It requires omniscient/omniauth and web-auth/webauthn-lib (framework-free: its CBOR, COSE and PKI
libraries, and the standalone Symfony components it is written on - serializer, property-info,
uid, clock). No bundle, no framework: the passkeys stay in your table, behind
`Omniauth\WebAuthn\Contract\Passkeys`, as `PasskeyRecord` values - the 13 fields of WebAuthn's
credential record, as omnibase's `userPasskey` table holds them.

The whole thing by hand - the in-memory stores of `Omniauth\Testing` stand in for yours, and
`Omniauth\WebAuthn\Testing\SoftwareAuthenticator` for the person's browser and device:

```php
<?php

require 'vendor/autoload.php';

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\Factor;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\WebAuthn\PasskeyMethod;
use Omniauth\WebAuthn\RelyingParty;
use Omniauth\WebAuthn\Testing\InMemoryPasskeys;
use Omniauth\WebAuthn\Testing\SoftwareAuthenticator;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;

$store = new InMemoryStore($ringo = new TestAccount('42', 'ringo', 'ringo@example.org', name: 'Ringo Starr'));
$passkeys = new InMemoryPasskeys($store);                  // yours: the userPasskey table

$session = [];                                             // $_SESSION, in a real page
$omniauth = new Omniauth(
    accounts: $store,
    methods: new Methods([
        new PasskeyMethod($store, $passkeys, new RelyingParty(id: 'example.org')),   // RELYING_PARTY_ID
    ]),
    state: new ArrayState($session),
);
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: '203.0.113.7');
$browser = new SoftwareAuthenticator('https://example.org');

// From the account's settings: the creation options, then what the browser made of them.
$enrolment = $omniauth->enrol(Factor::Passkey, $ringo);
$options = $enrolment->begin($context);                    // JSON for PublicKeyCredential.parseCreationOptionsFromJSON()
$credential = $browser->create($options->payload);         // navigator.credentials.create(), then credential.toJSON()
echo $enrolment->confirm($context, ['json' => json_encode($credential), 'label' => 'MacBook'])->isDone() ? "registered\n" : "refused\n";
// registered

// Signing in: the request options, then the assertion. No account named: the person picks the passkey.
$options = $omniauth->begin('passkey', $context);          // JSON for PublicKeyCredential.parseRequestOptionsFromJSON()
$assertion = $browser->get($options->payload);             // navigator.credentials.get(), then credential.toJSON()
$result = $omniauth->verify('passkey', $context, ['json' => json_encode($assertion)]);
echo $result->status->value, ' as ', $result->account->identifier, ' by ', implode(' + ', array_map(fn ($f) => $f->value, $result->passed)), "\n";
// authenticated as ringo by passkey
```

What your page does around it is the host's part: it sends `$options->payload` as it is (the
bridges add `status: "ok"` and `errorMessage: ""` around it, as web-auth/webauthn-symfony-bundle
does, for `assets/security/webauthn.js`), posts the browser's JSON back, checks the CSRF token of
the settings page, and on `Authenticated` renews its session id and keeps the account's handle.

No second factor follows a passkey (Marco's decision QA1): user verification is required at every
ceremony - the device, and the gesture or the code that unlocks it.

Run in omniauth's harness on 2026-10-25 (the block as it is, `Tests/DocsTest.php`), it prints:

```
registered
authenticated as ringo by passkey
```

Next: [the method](webauthn.md), [the records and the bundle](records.md).
