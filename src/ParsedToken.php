<?php

namespace STS\JWT;

use DateTimeImmutable;
use Exception;
use Illuminate\Support\Arr;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use STS\JWT\Exceptions\JwtExpiredException;
use STS\JWT\Exceptions\JwtValidationException;
use Lcobucci\JWT\Token\Parser;
use STS\JWT\Facades\JWT;

class ParsedToken
{
    protected bool $isValid = false;

    public function __construct(protected Plain $token)
    {
    }

    public static function fromString($jwt): ParsedToken
    {
        return new static(
            (new Parser(new JoseEncoder()))->parse($jwt)
        );
    }

    public function validateAll(string $id, $signingKey = null): self
    {
        (new Validator)->assert($this->token, ...$this->validationRules($id, $signingKey));

        $this->isValid = true;

        return $this;
    }

    /**
     * Performs validation and returns a boolean. Suppresses any exceptions thrown from validation.
     */
    public function isValid(string $id, $signingKey = null): bool
    {
        try {
            $this->validateAll($id, $signingKey);
        } catch (Exception $e) {
            return false;
        }

        return $this->isValid;
    }

    /**
     * Validates and throws a single, specific exception rather than the combined RequiredConstraintsViolated
     */
    public function validate(string $id, $signingKey = null): self
    {
        try {
            return $this->validateAll($id, $signingKey);
        } catch (RequiredConstraintsViolated $e) {
            throw Arr::first($e->violations());
        }
    }

    protected function validationRules(string $id, $signingKey): array
    {
        return array_filter([
            // Check the signature first. If this isn't valid, nothing else matter.
            new SignedWith(new Sha256(), InMemory::plainText($signingKey ?? JWT::signingKey())),

            // Check that we're withing the allowed timeframe
            new LooseValidAt(SystemClock::fromUTC()),

            // Optionally check that the token was intended for us
            config('jwt.validate.audience') ? new PermittedFor(JWT::defaultAudience()) : null,

            // And finally that it has the correct ID
            new IdentifiedBy($id)
        ]);
    }

    public function isExpired(): bool
    {
        return $this->token->isExpired(new DateTimeImmutable);
    }

    public function toArray(): array
    {
        return $this->token->claims()->all();
    }

    public function getPayload(): array
    {
        return array_diff_key($this->toArray(), array_flip(['jti','iss','aud','sub','iat','nbf','exp']));
    }

    public function get($name, $default = null)
    {
        return $this->token->claims()->get($name, $default);
    }

    public function __call($method, $parameters)
    {
        return call_user_func_array([$this->token, $method], $parameters);
    }
}