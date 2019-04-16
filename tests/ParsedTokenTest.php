<?php

class ParsedTokenTest extends \Orchestra\Testbench\TestCase
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
            'jwt.key'      => 'thisissigningkey',
            'jwt.audience' => 'myappaud',
            'jwt.issuer'   => 'myappiss'
        ]);
    }

    public function testToArray()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertTrue(is_array($token->toArray()));

        // We expect to have exp, jti, aud, and iss... plust the one extra 'foo' claim
        $this->assertEquals(5, count($token->toArray()));
        $this->assertArrayHasKey('foo', $token->toArray());
        $this->assertEquals('bar', $token->toArray()['foo']);
    }

    public function testGetPayload()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertTrue(is_array($token->getPayload()));

        // We expect to onlyh ave our one extra 'foo' claim
        $this->assertEquals(1, count($token->getPayload()));
        $this->assertArrayHasKey('foo', $token->getPayload());
        $this->assertEquals('bar', $token->getPayload()['foo']);
    }

    public function testGet()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertEquals("bar", $token->get("foo"));
        $this->assertNull($token->get("quz"));
        $this->assertEquals("default", $token->get("quz", "default"));
    }
}