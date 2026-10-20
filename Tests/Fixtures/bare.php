<?php

/*
 * omniauth/passkey in plain PHP: no bundle, no container, no framework. The
 * conductor built by hand on the in-memory stores; an account registers a
 * passkey from its settings (a software authenticator in the browser's
 * place), then signs in with it - no second factor, though a password asks
 * for one; the same assertion again; a forged signature. Prints what
 * happened and every class and file PHP loaded, as JSON. Argument: the
 * autoloader.
 */

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\EmailCode\EmailCodeMethod;
use Omniauth\Factor;
use Omniauth\Method\Methods;
use Omniauth\Omniauth;
use Omniauth\Passkey\PasskeyMethod;
use Omniauth\Passkey\RelyingParty;
use Omniauth\Passkey\Testing\InMemoryPasskeys;
use Omniauth\Passkey\Testing\SoftwareAuthenticator;
use Omniauth\Password\PasswordMethod;
use Omniauth\Result;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\RecordingSender;
use Omniauth\Testing\TestAccount;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

require $autoload = $argv[1];

$hasher = new NativePasswordHasher(cost: 4);
$store = new InMemoryStore($ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine'), emailCodeEnabled: true));
$passkeys = new InMemoryPasskeys($store);
$session = [];
$omniauth = new Omniauth($store, new Methods([
    new PasswordMethod($store, $store, $hasher),
    new EmailCodeMethod($store, $store->emailCodes(), new RecordingSender(), 'a-kernel-secret-of-thirty-two-bytes-or-more'),
    new PasskeyMethod($store, $passkeys, new RelyingParty('example.org')),
]), new ArrayState($session));
$context = new Context('https://example.org', 'example.org', '203.0.113.7');
$seen = static fn (Result $r) => ['status' => $r->status->value, 'account' => $r->account?->identifier, 'passed' => array_map(fn ($f) => $f->value, $r->passed), 'offered' => array_map(fn ($f) => $f->value, $r->offered), 'failure' => $r->failure?->value, 'reason' => $r->reason];
$authenticator = new SoftwareAuthenticator('https://example.org');

$enrolment = $omniauth->enrol(Factor::Passkey, $ringo);
$creation = $enrolment->begin($context);
$report['registration'] = [$creation->kind, $enrolment->confirm($context, ['json' => json_encode($authenticator->create($creation->payload))])->isDone(), count($passkeys->records)];

$report['password'] = $seen($omniauth->verify('password', $context, ['identifier' => 'ringo', 'password' => 'yellow-submarine']));
$omniauth->abandon();

$request = $omniauth->begin('passkey', $context);
$assertion = json_encode($authenticator->get($request->payload));
$report['passkey'] = $seen($omniauth->verify('passkey', $context, ['json' => $assertion]));
$report['again'] = $seen($omniauth->verify('passkey', $context, ['json' => $assertion]));

$impostor = (new SoftwareAuthenticator('https://example.org', credentialId: $authenticator->credentialId))->belongsTo('1');
$report['forged'] = $seen($omniauth->verify('passkey', $context, ['json' => json_encode($impostor->get($omniauth->begin('passkey', $context)->payload))]));
$report['counter'] = $passkeys->byCredentialId(base64_encode($authenticator->credentialId))->counter;

$report['loaded'] = [
    'symbols' => [...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()],
    'files' => array_map('realpath', get_included_files()),
    'eager' => array_map('realpath', array_values(is_file($files = dirname($autoload).'/composer/autoload_files.php') ? require $files : [])),
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
