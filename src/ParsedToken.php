<?php

namespace STS\JWT;

use Config;
use Exception;
use Lcobucci\JWT\Claim\Validatable;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use STS\JWT\Exceptions\JwtExpiredException;
use STS\JWT\Exceptions\JwtValidationException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

/**
 *
 */
class ParsedToken
{
    /** @var Token */
    protected $token;

    /** @var bool */
    protected $isValid = false;

    /**
     * @param Token $token
     */
    public function __construct(Token $token)
    {
        $this->token = $token;
    }

    /**
     * @param string $jwt
     *
     * @return ParsedToken
     */
    public static function fromString($jwt)
    {
        return new static(
            (new Parser())->parse($jwt)
        );
    }

    /**
     * Validates the token and throws exceptions for any failure encountered
     *
     * @param ValidationData|string $validationInput
     * @param null $signingKey
     *
     * @return ParsedToken
     * @throws JwtExpiredException
     * @throws JwtValidationException
     */
    public function validate($validationInput, $signingKey = null)
    {
        $this->validateRequiredClaims();
        $this->validateExpiration();
        $this->validateData($this->buildValidationData($validationInput));
        $this->verifySignature($signingKey);

        $this->isValid = true;

        return $this;
    }

    /**
     * Performs validation and returns a boolean. Suppresses any exceptions thrown from validation.
     *
     * @param $validationInput
     * @param null $signingKey
     *
     * @return bool
     */
    public function isValid($validationInput, $signingKey = null)
    {
        try {
            $this->validate($validationInput, $signingKey);
        } catch (Exception $e) {
            return false;
        }

        return $this->isValid;
    }

    /**
     * @throws JwtValidationException
     */
    protected function validateRequiredClaims()
    {
        if (!$this->token->hasClaim('exp')) {
            throw new JwtValidationException("Token expiration is missing", $this->token);
        }

        if (!$this->token->hasClaim('jti')) {
            throw new JwtValidationException("Token ID is missing", $this->token);
        }

        if (Config::get('jwt.validate.audience') && !$this->token->hasClaim('aud')) {
            throw new JwtValidationException("Token audience is missing", $this->token);
        }
    }

    /**
     * @throws JwtExpiredException
     */
    protected function validateExpiration()
    {
        // Yes this will be validated in the `validateData` loop, however I like having a dedicated error message
        // for this quite-common scenario
        if ($this->token->isExpired()) {
            throw new JwtExpiredException($this->token);
        }
    }

    /**
     * @param ValidationData $validationData
     *
     * @throws JwtValidationException
     */
    protected function validateData(ValidationData $validationData)
    {
        foreach ($this->getValidatableClaims() as $claim) {
            if (!$claim->validate($validationData)) {
                throw new JwtValidationException("JWT claim [{$claim->getName()}] is invalid", $this->token);
            }
        }
    }

    /**
     * @param null $signingKey
     *
     * @throws JwtValidationException
     */
    protected function verifySignature($signingKey = null)
    {
        if (!$this->token->verify(new Sha256(), $signingKey ?? JWTFacade::getSigningKey())) {
            throw new JwtValidationException("JWT signature is invalid", $this->token);
        }
    }

    /**
     * @return \Generator
     */
    protected function getValidatableClaims()
    {
        foreach ($this->token->getClaims() as $claim) {
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
    }

    /**
     * @param ValidationData|string $validationInput
     *
     * @return ValidationData
     */
    protected function buildValidationData($validationInput)
    {
        if (is_string($validationInput)) {
            $validationData = new ValidationData();
            $validationData->setId($validationInput);
        } else if ($validationInput instanceof ValidationData) {
            $validationData = $validationInput;
        } else {
            throw new \InvalidArgumentException("Invalid validation data provided");
        }

        if (!$validationData->has('aud')) {
            $validationData->setAudience(JWTFacade::getDefaultAudience());
        }

        return $validationData;
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return array_map(function($claim) {
            return (string) $claim;
        }, $this->token->getClaims());
    }

    /**
     * @return array
     */
    public function getPayload()
    {
        return array_diff_key($this->toArray(), array_flip(['jti','iss','aud','sub','iat','nbf','exp']));
    }

    /**
     * @param $name
     * @param null $default
     *
     * @return mixed|null
     */
    public function get($name, $default = null)
    {
        return $this->token->hasClaim($name)
            ? $this->token->getClaim($name)
            : $default;
    }

    /**
     * @param $method
     * @param $parameters
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        return call_user_func_array([$this->token, $method], $parameters);
    }
}