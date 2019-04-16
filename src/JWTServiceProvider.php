<?php

namespace STS\JWT;

use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
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