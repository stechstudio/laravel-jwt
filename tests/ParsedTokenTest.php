<?php

use Orchestra\Testbench\TestCase;
use STS\JWT\Facades\JWT;

class ParsedTokenTest extends TestCase
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
        $app['config']->set([
            'jwt.key'      => 'thisissigningkeythisissigningkey',
            'jwt.audience' => 'myappaud',
            'jwt.issuer'   => 'myappiss'
        ]);
    }

    public function testToArray()
    {
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertIsArray($token->toArray());

        // We expect to have exp, jti, aud, and iss... plus the one extra 'foo' claim
        $this->assertCount(5, $token->toArray());
        $this->assertArrayHasKey('foo', $token->toArray());
        $this->assertEquals('bar', $token->toArray()['foo']);
    }

    public function testGetPayload()
    {
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertIsArray($token->getPayload());

        // We expect to onlyh ave our one extra 'foo' claim
        $this->assertCount(1, $token->getPayload());
        $this->assertArrayHasKey('foo', $token->getPayload());
        $this->assertEquals('bar', $token->getPayload()['foo']);
    }

    public function testGet()
    {
        $token = JWT::parse(JWT::get("test-id", ["foo" => "bar"]));

        $this->assertEquals("bar", $token->get("foo"));
        $this->assertNull($token->get("quz"));
        $this->assertEquals("default", $token->get("quz", "default"));
    }
}