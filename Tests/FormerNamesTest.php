<?php

namespace Omniauth\WebAuthn\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** omniauth/passkey's names, aliases of omniauth/webauthn's classes for one release. */
final class FormerNamesTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function classes(): iterable
    {
        foreach (['PasskeyMethod', 'PasskeyRecord', 'RelyingParty', 'Contract\\Passkeys', 'Testing\\InMemoryPasskeys', 'Testing\\SoftwareAuthenticator'] as $class) {
            yield $class => [$class];
        }
    }

    #[DataProvider('classes')]
    public function testEachFormerNameIsTheNewClass(string $class): void
    {
        $former = 'Omniauth\\Passkey\\'.$class;
        self::assertTrue(@class_exists($former) || @interface_exists($former), $former);
        self::assertSame('Omniauth\\WebAuthn\\'.$class, (new \ReflectionClass($former))->getName(), $former);
    }

    public function testEachFormerNameSaysItIsDeprecated(): void
    {
        $files = glob(\dirname(__DIR__).'/Legacy/{,*/}*.php', \GLOB_BRACE) ?: [];
        self::assertCount(6, $files);
        foreach ($files as $file) {
            self::assertMatchesRegularExpression('~@trigger_error\(\'Omniauth\\\\Passkey\\\\[\w\\\\]+ is deprecated: use Omniauth\\\\WebAuthn\\\\[\w\\\\]+ \(omniauth/webauthn\)\.\', \\\\E_USER_DEPRECATED\);~', (string) file_get_contents($file), $file);
        }
    }
}
