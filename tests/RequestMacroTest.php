<?php

use Orchestra\Testbench\TestCase;
use STS\JWT\Facades\JWT;

class RequestMacroTest extends TestCase
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

    public function testGetClaimFromRequest()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);

        // Set the jwt id to match our route name
        $route->parameters = ['jwt' => JWT::get('test-id', ['foo' => 'bar'])];
        $request->setRouteResolver(function() use($route) { return $route; });

        $middleware->handle($request, function() { return "success"; }, 'test-id');

        // We can access claims right on the request object
        $this->assertEquals('test-id', $request->getClaim('jti'));
        $this->assertNull($request->getClaim('invalid'));
        $this->assertEquals('default', $request->getClaim('invalid', 'default'));

        // Ensure this gracefully falls back to default if no JWT is on the request
        $request = new \Illuminate\Http\Request();
        $this->assertEquals('default', $request->getClaim('invalid', 'default'));
    }

    public function testPayloadMergedOntoRequest()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);

        // Set the jwt id to match our route name
        $route->parameters = ['jwt' => JWT::get('test-id', ['foo' => 'bar'])];
        $request->setRouteResolver(function() use($route) { return $route; });

        $middleware->handle($request, function() { return "success"; }, 'test-id');
        $this->assertEquals('bar', $request->foo);
    }

    public function testPayloadNotMergedOntoRequest()
    {
        config(['jwt.merge' => false]);

        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);

        // Set the jwt id to match our route name
        $route->parameters = ['jwt' => JWT::get('test-id', ['foo' => 'bar'])];
        $request->setRouteResolver(function() use($route) { return $route; });

        $middleware->handle($request, function() { return "success"; }, 'test-id');
        $this->assertNull($request->foo);
    }
}