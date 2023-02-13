<?php

namespace STS\JWT\Exceptions;

use Lcobucci\JWT\Exception;
use Lcobucci\JWT\Validation\ConstraintViolation;
use RuntimeException;
use STS\JWT\ParsedToken;

class ValidationException extends RuntimeException implements Exception
{
    public ParsedToken $token;

    public function __construct(ConstraintViolation $previous, ParsedToken $token)
    {
        parent::__construct($previous->getMessage(), 0, $previous);

        $this->token = $token;
    }

    public static function factory(ConstraintViolation $exception, ParsedToken $token)
    {
        $class = match($exception->getMessage()) {
            "The token is not identified with the expected ID" => InvalidID::class,
            "The token is not allowed to be used by this audience" => InvalidAudience::class,
            "The token is expired" => TokenExpired::class,
            "Token signature mismatch" => InvalidSignature::class,
            default => static::class
        };

        return new $class($exception, $token);
    }
}