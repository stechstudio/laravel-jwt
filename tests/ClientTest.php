<?php

use Carbon\Carbon;
use Carbon\CarbonImmutable;
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
        $token = JWT::duration(Carbon::now()->addMinutes(10))->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(9)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(10)));
    }

    public function testLifetime()
    {
        $token = JWT::duration(600)->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(9)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(10)));

        /** @var Token $token */
        $token = JWT::duration(CarbonImmutable::now()->addMinutes(5))->getToken();

        $this->assertFalse($token->isExpired(CarbonImmutable::now()->addMinutes(4)));
        $this->assertTrue($token->isExpired(CarbonImmutable::now()->addMinutes(5)));
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