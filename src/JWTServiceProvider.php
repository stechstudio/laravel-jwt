<?php

namespace STS\JWT;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use STS\JWT\Exceptions\JwtValidationException;

class JWTServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->app['router']->aliasMiddleware('jwt', JwtValidationException::class);

        Request::macro('getClaim', function($name, $default = null) {
            return $this->get('jwt') instanceof ParsedToken
                ? $this->get('jwt')->get($name, $default)
                : $default;
        });
    }

    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'jwt');

        $this->app->bind(Client::class, function ($app) {
            return new Client(
                config('jwt.key'),
                config('jwt.lifetime'),
                config('jwt.issuer'),
                config('jwt.audience')
            );
        });
    }

    public function provides()
    {
        return [Client::class];
    }
}