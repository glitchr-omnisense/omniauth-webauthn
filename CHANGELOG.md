# Changelog

Every version of omniauth/webauthn, newest first ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
[Semantic Versioning](https://semver.org/)). A release's notes are its section here: the release
workflow refuses a tag without one.

## [Unreleased]

## [1.0.0] - 2026-11-13

The first stable version. It requires `omnisense/omniauth` `^1.0` with no stability flag, so `composer require omniauth/webauthn` installs it in a project with Composer's default minimum-stability; the 1.x series follows semantic versioning. A tag `vX.Y.Z` is released by `.github/workflows/release.yml` once the package's CI passes on it.

Omniauth's WebAuthn over web-auth/webauthn-lib, under any PHP host - passkeys: the sign-in (request options, then the assertion checked: origin, relying party, user verification required, counter and backup flags kept) and the registration (creation options, then the attestation checked), on the credential record as omnibase's userPasskey table holds it - the 13 fields of WebAuthn's CredentialRecord, in their base64 text - so a passkey registered by web-auth/webauthn-symfony-bundle signs in here and one registered here is read by the bundle. A software authenticator (P-256) signs real assertions in tests. Formerly omniauth/passkey, which it replaces (the Omniauth\Passkey\ names stay aliases for one release).
