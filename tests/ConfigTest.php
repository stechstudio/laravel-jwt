<?php

class ConfigTest extends \Orchestra\Testbench\TestCase
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

    public function testSigningKeyWithAppKey()
    {
        putenv("APP_KEY=thisisappkey");

        $this->refreshApplication();

        $this->assertEquals('thisisappkey', config('jwt.key'));
    }

    public function testSigningKeyWithExplicitJwtKey()
    {
        putenv("APP_KEY=thisisappkey");
        putenv("JWT_SIGNING_KEY=thisisjwtkey");

        $this->refreshApplication();

        $this->assertEquals('thisisjwtkey', config('jwt.key'));
    }
}