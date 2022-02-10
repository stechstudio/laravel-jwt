<?php

namespace STS\JWT;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;

class JWTServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->app['router']->aliasMiddleware('jwt', JwtValidateMiddleware::class);

        Request::macro('setToken', function(ParsedToken $token) {
            $this->token = $token;
        });

        Request::macro('getClaim', function($name, $default = null) {
            return $this->token && $this->token instanceof ParsedToken
                ? $this->token->get($name, $default)
                : $default;
        });
    }

    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'jwt');

        $this->app->bind(Client::class, function ($app) {
            if (Str::startsWith($key = config('jwt.key'), 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            return new Client(
                $key,
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