<?php

namespace STS\JWT;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Plain;

/**
 * @mixin Builder
 */
class Client
{
    protected Builder $builder;
    protected string $signingKey;
    protected bool $isSigned = false;
    protected array $configures = [];

    public function __construct(
        protected string $defaultSigningKey,
        protected int|CarbonImmutable $lifetime,
        protected string $issuer,
        protected string $audience)
    {
        $this->reset();
    }

    public function reset(): self
    {
        $this->builder = new Builder(new JoseEncoder(), ChainedFormatter::default());
        $this->lifetime($this->lifetime);
        $this->configures = [];
        $this->signingKey = $this->defaultSigningKey;
        $this->isSigned = false;

        return $this;
    }

    public function defaultAudience(): string
    {
        return $this->audience;
    }

    public function defaultIssuer(): string
    {
        return $this->issuer;
    }

    public function signWith(string $signingKey): self
    {
        $this->signingKey = $signingKey;

        return $this;
    }

    public function signingKey(): string
    {
        return $this->signingKey;
    }

    public function getToken(): Plain
    {
        // Ensure we have an audience set
        if (!in_array('permittedFor', $this->configures)) {
            $this->builder->permittedFor($this->audience);
        }

        // Ensure we have an issuer set
        if (!in_array('issuedBy', $this->configures)) {
            $this->builder->issuedBy($this->issuer);
        }

        $token = $this->builder->getToken(new Sha256(), InMemory::plainText($this->signingKey()));

        $this->reset();

        return $token;
    }

    public function __toString(): string
    {
        return (string) $this->getToken();
    }

    public function expiresAt(DateTime|DateTimeImmutable $expiration): self
    {
        if($expiration instanceof DateTime) {
            $expiration = DateTimeImmutable::createFromMutable($expiration);
        }

        $this->builder->expiresAt($expiration);

        return $this;
    }

    public function lifetime(int $lifetime): self
    {
        $this->builder->expiresAt(CarbonImmutable::now()->addSeconds($lifetime));

        return $this;
    }

    public function withClaims(array $claims = []): self
    {
        foreach ($claims AS $key => $value) {
            $this->builder->withClaim($key, $value);
        }

        return $this;
    }

    public function get(string$id, array $claims = [], int|DateTimeInterface $lifetime = null, string $signingKey = null): string
    {
        if ($signingKey !== null) {
            $this->signWith($signingKey);
        }

        if(is_int($lifetime)) {
            $this->lifetime($lifetime);
        }

        if($lifetime instanceof DateTimeInterface) {
            $this->expiresAt($lifetime);
        }

        return $this
            ->withClaims($claims)
            ->identifiedBy($id)
            ->getToken()
            ->toString();
    }

    public function setAudience(string $audience): self
    {
        $this->builder->permittedFor($audience);
        $this->claims[] = "aud";

        return $this;
    }

    public function setIssuer(string $issuer)
    {
        $this->builder->issuedBy($issuer);
        $this->claims[] = "iss";

        return $this;
    }

    public function __call(string $method, array $parameters): mixed
    {
        $this->configures[] = $method;

        $result = call_user_func_array([$this->builder, $method], $parameters);

        return $result instanceof Builder
            ? $this
            : $result;
    }

    public function parse(string $jwt): ParsedToken
    {
        return ParsedToken::fromString($jwt);
    }
}