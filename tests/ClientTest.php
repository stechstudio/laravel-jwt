<?php

use Lcobucci\JWT\Signer\Hmac\Sha256;

class ClientTest extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app)
    {
        return [\STS\JWT\JWTServiceProvider::class];
    }

    protected function getPackageAliases($app)
    {
        return [
            'JWT' => \STS\JWT\JWTFacade::class
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set([
            'jwt.key' => 'thisissigningkey',
            'jwt.audience' => 'myappaud',
            'jwt.issuer' => 'myappiss'
        ]);
    }

    public function testSigningKeyInjected()
    {
        $this->assertEquals('thisissigningkey', JWT::getSigningKey());
    }

    public function testTokenAlwaysSigned()
    {
        /** @var \Lcobucci\JWT\Token $token */
        $token = JWT::getToken();

        $this->assertTrue(
            $token->verify(new Lcobucci\JWT\Signer\Hmac\Sha256(), "thisissigningkey")
        );
    }

    public function testAudience()
    {
        // Default audience
        $this->assertEquals('myappaud', JWT::getToken()->getClaim('aud'));

        // Explicitly set
        $this->assertEquals('test-aud', JWT::setAudience('test-aud')->getToken()->getClaim('aud'));
    }

    public function testIssuer()
    {
        // Default issuer
        $this->assertEquals('myappiss', JWT::getToken()->getClaim('iss'));

        // Explicitly set
        $this->assertEquals('test-iss', JWT::setIssuer('test-iss')->getToken()->getClaim('iss'));
    }

    public function testId()
    {
        $this->assertEquals('test-id', JWT::setId('test-id')->getToken()->getClaim('jti'));
    }

    public function testPayload()
    {
        /** @var \Lcobucci\JWT\Token $token */
        $token = JWT::setId('test-id')->setClaims(['foo' => 'bar'])->getToken();

        $this->assertEquals('bar', $token->getClaim('foo'));
    }

    public function testLifetime()
    {
        /** @var \Lcobucci\JWT\Token $token */
        $token = JWT::setLifetime(600)->getToken();

        $this->assertFalse($token->isExpired(\Carbon\Carbon::now()->addMinutes(9)));
        $this->assertTrue($token->isExpired(\Carbon\Carbon::now()->addMinutes(10)));

        /** @var \Lcobucci\JWT\Token $token */
        $token = JWT::setLifetime(\Carbon\Carbon::now()->addMinutes(5))->getToken();

        $this->assertFalse($token->isExpired(\Carbon\Carbon::now()->addMinutes(4)));
        $this->assertTrue($token->isExpired(\Carbon\Carbon::now()->addMinutes(5)));
    }

    public function testQuickGet()
    {
        $jwt = JWT::get('test-id', ['foo' => 'bar'], 1800);

        $this->assertTrue(is_string($jwt));

        $token = (new \Lcobucci\JWT\Parser())->parse($jwt);

        $this->assertTrue($token instanceof \Lcobucci\JWT\Token);

        $this->assertEquals('test-id', $token->getClaim('jti'));
        $this->assertEquals('bar', $token->getClaim('foo'));
        $this->assertFalse($token->isExpired(\Carbon\Carbon::now()->addMinutes(29)));
        $this->assertTrue($token->isExpired(\Carbon\Carbon::now()->addMinutes(30)));
        $this->assertTrue($token->verify(new Lcobucci\JWT\Signer\Hmac\Sha256(), "thisissigningkey"));
    }
}