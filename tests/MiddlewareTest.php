<?php

use Lcobucci\JWT\Validation\ConstraintViolation;
use Orchestra\Testbench\TestCase;
use STS\JWT\Facades\JWT;

class MiddlewareTest extends TestCase
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

    public function testMissingToken()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();

        $this->expectException(\Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException::class);
        $middleware->findJWT($request);
    }

    public function testTokenInRequest()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();

        $request = new \Illuminate\Http\Request();
        $request->offsetSet("jwt", "foobar");

        $this->assertEquals("foobar", $middleware->findJWT($request));

        $request = new \Illuminate\Http\Request();
        $request->offsetSet("token", "baz");

        $this->assertEquals("baz", $middleware->findJWT($request));
    }

    public function testTokenInRoute()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();

        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);
        $route->parameters = ['jwt' => 'foobar'];
        $request->setRouteResolver(function() use($route) { return $route; });

        $this->assertEquals("foobar", $middleware->findJWT($request));

        $route->parameters = ['token' => 'baz'];
        $this->assertEquals("baz", $middleware->findJWT($request));
    }

    public function testTokenInAuthorizationHeader()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();

        $request = new \Illuminate\Http\Request();
        $request->headers->set('Authorization', 'Basic' . base64_encode('username:foobar'));

        $this->assertEquals("foobar", $middleware->findJWT($request));

        $request = new \Illuminate\Http\Request();
        $request->headers->set('Authorization', 'Token baz');
        $this->assertEquals("baz", $middleware->findJWT($request));
    }

    public function testIdFromRouteName()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);

        // Set the jwt id to match our route name
        $route->parameters = ['jwt' => JWT::get('my.route')];
        $route->action = ['as' => 'my.route'];
        $request->setRouteResolver(fn() => $route);

        $this->assertEquals("success", $middleware->handle($request, function() { return "success"; }));

        // Change the route name and the JWT won't pass
        $route->action = ['as' => 'new.name'];

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');
        $this->assertEquals("success", $middleware->handle($request, function() { return "success"; }));
    }

    public function testSpecifiedId()
    {
        $middleware = new \STS\JWT\JwtValidateMiddleware();
        $request = new \Illuminate\Http\Request();
        $route = new \Illuminate\Routing\Route([], '', []);

        // Set the jwt id to match our route name
        $route->parameters = ['jwt' => JWT::get('test-id')];
        $request->setRouteResolver(function() use($route) { return $route; });

        $this->assertEquals("success", $middleware->handle($request, function() { return "success"; }, 'test-id'));

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('The token is not identified with the expected ID');
        $this->assertEquals("success", $middleware->handle($request, function() { return "success"; }, 'different-id'));
    }
}