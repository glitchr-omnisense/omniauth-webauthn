<?php

namespace Omniauth\WebAuthn\Tests;

use Omniauth\Omniauth;
use Omniauth\WebAuthn\PasskeyMethod;
use PHPUnit\Framework\TestCase;

/**
 * omniauth/webauthn with no framework: in PHP processes of their own (this
 * one has loaded PHPUnit), a whole registration and sign-in by hand, and
 * every class of the package loaded. Nothing may come from outside but
 * omniauth, webauthn-lib and what it requires - its CBOR, COSE and PKI
 * libraries, and the standalone Symfony components it is written on
 * (serializer, property-info, property-access, string, uid, clock) - the PSR
 * interfaces and symfony/password-hasher: no class of a framework (no
 * kernel, container, HTTP foundation, security), of the bundle, of Doctrine
 * or of an application, though the harness has them installed.
 */
final class BareTest extends TestCase
{
    private const FOREIGN = '~^(?:Symfony\\\\(?!Component\\\\(?:PasswordHasher|Serializer|PropertyInfo|PropertyAccess|Uid|Clock|TypeInfo|String)\\\\|Polyfill\\\\)|Webauthn\\\\Bundle\\\\|Doctrine\\\\(?!Deprecations\\\\)|(?:Illuminate|Laravel|Twig|Scheb|Lcobucci|OTPHP|League|Omnibridge|Base|App)\\\\)~';
    private const ALLOWED_FILES = '~/vendor/(?:psr/[\w-]+|symfony/(?:password-hasher|serializer|property-info|property-access|uid|clock|type-info|string|polyfill-[\w-]+|deprecation-contracts)|web-auth/(?:webauthn-lib|cose-lib)|spomky-labs/(?:cbor-php|pki-framework)|brick/math|paragonie/constant_time_encoding|phpdocumentor/[\w-]+|phpstan/phpdoc-parser|webmozart/assert|doctrine/deprecations|composer)/|/vendor/autoload\.php$~';

    public function testARegistrationAndASignInByHandLoadNothingElse(): void
    {
        $report = self::php([__DIR__.'/Fixtures/bare.php', self::autoload()]);

        self::assertSame(['json', true, 1], $report['registration']);
        self::assertSame(['second-factor-required', ['email-code']], [$report['password']['status'], $report['password']['offered']], 'a password asks for the code by e-mail');
        self::assertSame(['authenticated', 'ringo', ['passkey']], [$report['passkey']['status'], $report['passkey']['account'], $report['passkey']['passed']], 'a passkey does not (QA1)');
        self::assertSame(['failed', 'expired'], [$report['again']['status'], $report['again']['failure']], 'the same assertion again: its challenge is gone');
        self::assertSame(['failed', 'bad-credentials', 'invalid-assertion'], [$report['forged']['status'], $report['forged']['failure'], $report['forged']['reason']]);
        self::assertSame(2, $report['counter']);

        self::assertContains(PasskeyMethod::class, $report['loaded']['symbols']);
        self::assertContains('Webauthn\AuthenticatorAssertionResponseValidator', $report['loaded']['symbols']);
        self::assertSame([], self::foreign($report['loaded']['symbols']));
        self::assertSame([], self::outside($report['loaded']['files'], $report['loaded']['eager']));
    }

    public function testEveryClassLoadsWithTheRequiredPackagesAlone(): void
    {
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\WebAuthn']);

        self::assertContains(PasskeyMethod::class, $report['loaded']);
        self::assertContains('Omniauth\WebAuthn\Testing\SoftwareAuthenticator', $report['loaded']);
        self::assertContains('Omniauth\WebAuthn\PasskeyRecord', $report['loaded']);
        self::assertSame([], self::foreign($report['symbols']));
        self::assertSame([], self::outside($report['files'], $report['eager']));
    }

    /** The check is not blind: a class of the bundle, once loaded, is seen. */
    public function testTheReportSeesWhatIsLoaded(): void
    {
        $bundle = 'Webauthn\Bundle\Doctrine\Type\Base64BinaryDataType';
        if (!class_exists($bundle)) {
            self::markTestSkipped('web-auth/webauthn-symfony-bundle is not installed.');
        }
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\WebAuthn', $bundle]);

        self::assertContains($bundle, self::foreign($report['symbols']));
        self::assertNotEmpty(preg_grep('~/webauthn-symfony-bundle/|/doctrine/dbal/~', self::outside($report['files'], $report['eager'])));
    }

    /** @return list<string> */
    private static function foreign(array $symbols): array
    {
        return array_values(preg_grep(self::FOREIGN, $symbols));
    }

    /**
     * The files loaded from outside this package, omniauth's core and the
     * libraries allowed - but those Composer includes for every package at start (autoload
     * "files"), which say nothing of what this one uses.
     *
     * @return list<string>
     */
    private static function outside(array $files, array $eager): array
    {
        $roots = [realpath(\dirname(__DIR__)).'/', realpath(\dirname((string) (new \ReflectionClass(Omniauth::class))->getFileName())).'/'];
        $eager = array_map('dirname', array_filter($eager));

        return array_values(array_filter($files, static fn (?string $file) => null !== $file
            && [] === array_filter($roots, static fn (string $root) => str_starts_with($file, $root) && !str_starts_with(substr($file, \strlen($root)), 'vendor/'))
            && !\in_array(\dirname($file), $eager, true)
            && !preg_match(self::ALLOWED_FILES, $file)));
    }

    /** The autoloader that knows this package and its tests. */
    private static function autoload(): string
    {
        foreach (\Composer\Autoload\ClassLoader::getRegisteredLoaders() as $vendor => $loader) {
            if ($loader->findFile(PasskeyMethod::class) && $loader->findFile(Fixtures\Kit::class)) {
                return $vendor.'/autoload.php';
            }
        }
        self::markTestSkipped('No autoloader knows omniauth/webauthn\'s tests.');
    }

    /** @return array<string, mixed> */
    private static function php(array $arguments): array
    {
        $process = proc_open([\PHP_BINARY, ...$arguments], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        $status = proc_close($process);
        $report = json_decode($out, true);
        self::assertSame(0, $status, $err.$out);
        self::assertIsArray($report, $err.$out);

        return $report;
    }
}
