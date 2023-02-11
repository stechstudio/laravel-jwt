# Laravel JWT helper

[![Latest Version on Packagist](https://img.shields.io/packagist/v/stechstudio/laravel-jwt.svg?style=flat-square)](https://packagist.org/packages/stechstudio/laravel-jwt)
[![Build Status](https://img.shields.io/travis/stechstudio/laravel-jwt/master.svg?style=flat-square)](https://travis-ci.org/stechstudio/laravel-jwt)
[![Quality Score](https://img.shields.io/scrutinizer/g/stechstudio/laravel-jwt.svg?style=flat-square)](https://scrutinizer-ci.com/g/stechstudio/laravel-jwt)

Work with JWTs in your Laravel app? You may find this helpful.

This package wraps the excellent [lcobucci/jwt](https://github.com/lcobucci/jwt) library with the following benefits:

1) `JWT` facade with helper methods to quickly generate and parse tokens.
2) Enforces a minimal set of claims for generated tokens, like `aud`, `iss`, and `exp`.
3) Validate parsed tokens to ensure our required claims are set properly with signature present and valid.
4) HTTP Middleware to validate a route-specific JWT
5) Request macro to easily access route-specific JWT claims

## Quickstart

### Installation

```php
composer require stechstudio/laravel-jwt
```

### Simple example

You can generate a simple JWT like this:

```php
$jwt = JWT::get('token-id', ['myclaim' => 'somevalue']);
```

This will generate a token with the ID provided and an array of claims, returning the string token.

### Change lifetime

The default token expiration is set to 10 minutes which you can configure, or you can specify a custom lifetime value as a third parameter when creating the token:

```php
$jwt = JWT::get('token-id', ['anything' => 'here'], 3600);
```

This token will expire in one hour. You can also specify the lifetime with Carbon:

```php
$jwt = JWT::get('token-id', ['anything' => 'here'], Carbon\Carbon::now()->addMinutes(60));
```

### Change signing key

If you are generating a JWT that will be consumed by a different app (very common use case in our company) you can specify the signing key as the fourth parameter.

```php
$jwt = JWT::get('token-id', ['anything' => 'here'], 3600, config('services.otherapp.key'));
```

## Configuration

This package tries to pick sane defaults, while also allowing you to change configs through your .env file.

**Signature key**

Every token is signed, that's a strong opinion of this package. By default the `APP_KEY` in your .env file is used for the signing key, or you can provide a dedicated `JWT_SIGNING_KEY` instead.

**Lifetime**

Default lifetime is 600 seconds / 10 minutes. You can change the default by specifying the number of seconds as `JWT_LIFETIME`.

**Issuer**

The default token issuer (`iss` claim) is your `APP_NAME` lowercase. You can specify a different issuer name via `JWT_ISSUER`.

**Audience**

 The default token audience (`aud` claim) is your `APP_NAME` lowercase. You can specify a different issuer name via `JWT_AUDIENCE`.
 
 ## Building tokens fluently
 
 So far we've looked at the `JWT::get()` helper method which is super quick for simple needs. 
 
For more control over your token you can create it fluently instead. 
 
You can use any of the methods provided by the [underlying `Builder` class](https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/), along with a few new ones like `signWith`.
 
 ```php
 $token = JWT::setId('my-token-id')
    ->signWith('custom-signing-key')
    ->duration(3600)
    ->issuedBy("my-app")
    ->permittedFor("receiving-app")
    ->withClaim('myclaim', 'any value')
    ->getToken();
 ```
 
 ## Parse received tokens
 
 You can parse a JWT string into a token:
 
 ```php
 $token = JWT::parse("... JWT string ...");
 ```
 
 An exception will be thrown if the JWT cannot be parsed.
 
 ## Validate received tokens
 
 Just as this package has opinions on what a generated token should include, we want to ensure those minimums are set appropriately on any received tokens.
 
 After parsing a received token, simply call `isValid` or `validate`, depending on whether you want a boolean result or exceptions thrown. Make sure to pass in the expected token ID.
 
 ```php
$token = JWT::parse("... JWT string ...");

$token->isValid('expected-token-id'); // Returns true or false

$token->validate('expected-token-id'); // Throws exceptions for any validation failure
 ```
 
 At this point you can be certain that the token:
  
 1) Has the expected ID
 2) Is intended for your app (`aud` claim matches the configured audience)
 3) Is signed, and the signature is verified (using the configured signature key)
 4) Has an expiration claim, and has not yet expired 
 
 ## Retrieving claims
 
 Once you've parsed and validated a token, you can retrieve all token claims with `getClaims` or simply `toArray`. 
 
 If you'd like to just retrieve your custom payload claims, use `getPayload`;
 
 ```php
 // Make our string token
 $jwt = JWT::get('token-id', ['foo' => 'bar']);
 
 // Parse it and validate
 $token = JWT::parse($jwt)->validate('token-id');
 
 // Ignore registered claims, just get our custom claims
 $token->getPayload(); // [ foo => bar ]
 ```
 
 Or to retrieve just one claim, use `get` passing in the name of the claim. You can optionally pass in a default value as the second parameter;
 
 ```php
 $token->get("foo"); // bar
 
 $token->get("invalid"); // null
 
 $token->get("invalid", "quz"); // quz
 ```
 
## Route middleware

We frequently use JWTs to authorize a request. These are sometimes generated and consumed by the same app, but more frequently they are for cross-app authorization.

You can use the included `jwt` middleware to validate a JWT request. The middleware will look for the JWT in a number of places:
 
1) As a request parameter named `jwt` or `token`
2) As a route paramater named `jwt` or `token`
3) In the Authorization header either as `Token JWT` or `Bearer :base64encodedJWT`

If a token is found in any of these locations it will be parsed and validated. 

### Token ID

By default the token ID will be expected to match the route name.

For example, with this following route the token will need an ID of `my.home`:

```php
Route::get('/home', 'Controller@home')->name('my.home')->middleware('jwt');
```

You can also specify the required ID by passing it as a middleware parameter:

```php
Route::get('/home', 'Controller@home')->middleware('jwt:expected-id');
```

## Access claims on request

### All token claims

The Laravel `Request` has a `getClaim` macro on it so you can grab claims from anywhere.

Example when injecting `$request` into a controller method:

```php
use Illuminate\Http\Request;

class Controller {
    public function home(Request $request)
    {
        echo $request->getClaim('aud'); // The token audience    
    }
}
```

### Custom payload merged

The token payload (custom claims added to the JWT, not part of the core registered claim set) is merged onto the request attributes, so you can access these just like any other request attribute.

If the JWT has a `foo` claim, you can directly access `$request->foo` or `$request->get('foo')` or even `request('foo')` using the global request helper.

_**Note**: When the payload is merged onto the request, there is a chance that we are stomping on some existing request attributes. Because we **really** trust the payload in a validated JWT, we prefer this behavior. However if you want to disable set `JWT_MERGE_PAYLOAD=false` in your .env file._  