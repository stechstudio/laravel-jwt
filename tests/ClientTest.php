<?php

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use STS\JWT\Facades\JWT;

class ClientTest extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app): array
    {
        return [\STS\JWT\JWTServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'JWT' => \STS\JWT\Facades\JWT::class
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set(['jwt' => [
            'key' => 'thisissigningkeythisissigningkey',
            'audience' => 'myappaud',
            'issuer' => 'myappiss',
            'lifetime' => 900,
            'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'chained_formatter' => "default",
        ]]);
    }

    public function testSigningKeyInjected()
    {
        $this->assertEquals('thisissigningkeythisissigningkey', JWT::signingKey());
    }

    public function testBase64SigningKey()
    {
        config(['jwt.key' => 'base64:' . base64_encode('thisissigningkeythisissigningkey')]);

        $this->assertEquals('thisissigningkeythisissigningkey', JWT::signingKey());
    }

    public function testTokenAlwaysSigned()
    {
        /** @var Token $token */
        $token = JWT::getToken();

        $this->assertTrue(
            (new Validator())->validate(
                $token,
                new SignedWith(new Sha256(), InMemory::plainText("thisissigningkeythisissigningkey"))
            )
        );
    }

    public function testAudience()
    {
        // Default audience
        $this->assertTrue(JWT::getToken()->isPermittedFor('myappaud'));

        // Explicitly set
        $this->assertTrue(JWT::permittedFor('test-aud')->getToken()->isPermittedFor('test-aud'));
    }

    public function testIssuer()
    {
        // Default issuer
        $this->assertTrue(JWT::getToken()->hasBeenIssuedBy('myappiss'));

        // Explicitly set
        $this->assertTrue(JWT::issuedBy('test-iss')->getToken()->hasBeenIssuedBy('test-iss'));
    }

    public function testId()
    {
        $this->assertTrue(JWT::identifiedBy('test-id')->getToken()->isIdentifiedBy('test-id'));
    }

    public function testPayload()
    {
        /** @var Token $token */
        $token = JWT::identifiedBy('test-id')->withClaims(['foo' => 'bar'])->getToken();

        $this->assertEquals('bar', $token->claims()->get('foo'));
    }

    public function testMutableDatetimeConversion()
    {
        $token = JWT::expiresAt(Carbon::now()->addMinutes(10))->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(9)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(10)));
    }

    public function testLifetime()
    {
        $token = JWT::lifetime(600)->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(9)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(10)));

        /** @var Token $token */
        $token = JWT::expiresAt(CarbonImmutable::now()->addMinutes(5))->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(4)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(5)));
    }

    public function testDefaultSigner()
    {
        $token = JWT::expiresAt(Carbon::now()->addMinutes(10))->getToken();

        $this->assertTrue(
            (new Validator())->validate(
                $token,
                new SignedWith(new Sha256(), InMemory::plainText("thisissigningkeythisissigningkey"))
            )
        );
    }

    public function testRsaSha256Signer()
    {
        $rsa = new \Lcobucci\JWT\Signer\Rsa\Sha256();
        $privateKey = file_get_contents(__DIR__ . '/keys/jwtRS256.key');
        $publicKey = InMemory::plainText(file_get_contents(__DIR__ . '/keys/jwtRS256.key.pub'));

        config(['jwt.signer' => \Lcobucci\JWT\Signer\Rsa\Sha256::class]);

        $token = JWT::get('test-id', ['foo' => 'bar'], 1800, $privateKey);

        $parsedToken = (new Parser(new JoseEncoder()))->parse($token);

        $this->assertTrue(
            (new Validator())->validate(
                $parsedToken,
                new SignedWith($rsa, $publicKey)
            )
        );
    }

    public function testDefaultTimestampFormatter()
    {
        $time = Carbon::now()->addMinutes(10);
        $token = JWT::expiresAt($time)->getToken();

        $parts = array_map('base64_decode', explode('.', $token->toString()));

        $this->assertEquals(
            $time->format('U.u'),
            json_decode($parts[1])->exp
        );
    }

    public function testUnixTimestampFormatter()
    {
        config(['jwt.chained_formatter' => ChainedFormatter::withUnixTimestampDates()]);

        $time = Carbon::now()->addMinutes(10);
        $token = JWT::expiresAt($time)->getToken();

        $parts = array_map('base64_decode', explode('.', $token->toString()));

        $this->assertEquals(
            $time->format('U'),
            json_decode($parts[1])->exp
        );
    }

    public function testQuickGet()
    {
        $jwt = JWT::get('test-id', ['foo' => 'bar'], 1800);

        $this->assertIsString($jwt);

        $token = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertTrue($token->isIdentifiedBy('test-id'));
        $this->assertEquals('bar', $token->claims()->get('foo'));
        $this->assertFalse($token->isExpired(Carbon::now()->addMinutes(29)));
        $this->assertTrue($token->isExpired(Carbon::now()->addMinutes(30)));
        $this->assertTrue(
            (new Validator())->validate(
                $token,
                new SignedWith(new Sha256(), InMemory::plainText("thisissigningkeythisissigningkey"))
            )
        );
    }
}

