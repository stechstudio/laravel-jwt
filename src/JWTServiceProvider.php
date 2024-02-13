<?php

namespace STS\JWT;

use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Lcobucci\JWT\Encoding\ChainedFormatter;

class JWTServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/jwt.php' => config_path('jwt.php'),
        ]);

        $this->app['router']->aliasMiddleware('jwt', JwtValidateMiddleware::class);

        Request::macro('setToken', function(ParsedToken $token) {
            $this->attributes->set('token', $token);
        });

        Request::macro('getClaim', function($name, $default = null) {
            return $this->attributes->has('token') && $this->attributes->get('token') instanceof ParsedToken
                ? $this->attributes->get('token')->get($name, $default)
                : $default;
        });
    }

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/jwt.php', 'jwt');

        $this->app->bind(Client::class, function ($app) {
            if (Str::startsWith($key = config('jwt.key'), 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            $signer = config('jwt.signer');

            $chainedFormatter = match(true) {
                config('jwt.chained_formatter') instanceof ChainedFormatter => config('jwt.chained_formatter'),
                config('jwt.chained_formatter') === "unix" => ChainedFormatter::withUnixTimestampDates(),
                default => ChainedFormatter::default()
            };

            return new Client(
                $key,
                new $signer(),
                $chainedFormatter,
                config('jwt.lifetime'),
                config('jwt.issuer'),
                config('jwt.audience')
            );
        });
    }

    public function provides(): array
    {
        return [Client::class];
    }
}
