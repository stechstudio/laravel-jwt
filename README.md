# Laravel JWT helper

Work with JWTs in your Laravel app? You may find this helpful.

This package wraps the excellent [lcobucci/jwt](https://github.com/lcobucci/jwt) library with the following benefits:

1) `JWT` facade with helper methods to quickly generate and parse tokens.
2) Enforces a minimal set of claims for generated tokens, like `aud`, `iss`, and `exp`. 
3) Always signs tokens, always.
4) Validate parsed tokens to ensure our required claims are set properly with signature present and valid.
5) HTTP Middleware to validate a route-specific JWT
6) Request macro to easily access route-specific JWT claims

## Quickstart

Get it installed:

```php
composer require stechstudio/laravel-jwt
```

And now generate a super-simple JWT:

```php
$jwt = JWT::get('token-id', ['anything' => 'here']);
```

This will generate a token with the ID provided and an array of claims, returning the string token.

The default token expiration is set to 10 minutes which you can configure, or you can specify a custom lifetime value as a third parameter when creating the token:

```php
$jwt = JWT::get('token-id', ['anything' => 'here'], 3600);
```

This token will expire in one hour. You can also specify the lifetime with Carbon:

```php
$jwt = JWT::get('token-id', ['anything' => 'here'], Carbon\Carbon::now()->addMinutes(60));
```

## Configuration

**Signature key**

Every token is signed, that's is one strong opinion of this package. By default the `APP_KEY` in your .env file is used for the signing key, or you can provide a dedicated `JWT_SIGNING_KEY` instead.

**Lifetime**

Default lifetime is 600 seconds / 10 minutes. You can change the default by specifying the number of seconds as `JWT_LIFETIME` in your .env file.

**Issuer**

The default token issuer (`iss` claim) is your `APP_NAME` lowercase. You can specify a different issuer name via `JWT_ISSUER`.

**Audience**

 The default token audience (`aud` claim) is your `APP_NAME` lowercase. You can specify a different issuer name via `JWT_AUDIENCE`.
 
 ## Building tokens fluently
 
 So far we've looked at the `JWT::get()` helper method which is super quick, yet limited. 
 
 For more control over your token you can create it fluently instead. 
 
 ```php
 $token = JWT::setId('my-token-id')
    ->setSigningKey('custom-signing-key')
    ->setLifetime(3600)
    ->setIssuer("my-app")
    ->setAudience("receiving-app")
    ->set('anything', 'here')
    ->getToken();
 ```
 
 You can use any of the underlying methods from the [Builder](https://github.com/lcobucci/jwt/blob/3.2/README.md#user-content-creating).
 
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
 2) Is signed, and the signature is verified (using the configured signature key)
 3) Has an expiration claim, and has not yet expired 
 
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