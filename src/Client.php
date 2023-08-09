<?php

namespace STS\JWT;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Support\Traits\Conditionable;
use Illuminate\Support\Traits\ForwardsCalls;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Plain;

/**
 * @mixin Builder
 */
class Client
{
    use ForwardsCalls, Conditionable;

    protected Builder $builder;
    protected array $configures = [];

    public function __construct(
        protected string $signingKey,
        protected Signer $signer,
        protected ChainedFormatter $chainedFormatter,
        protected int|CarbonImmutable $lifetime,
        protected string $issuer,
        protected string $audience)
    {
        $this->builder = new Builder(new JoseEncoder(), $this->chainedFormatter);
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

    public function audience(): string
    {
        return $this->audience;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function getToken(): Plain
    {
        // Set our own default audience, issuer, and expiration if none has been set so far
        in_array('permittedFor', $this->configures) || $this->permittedFor($this->audience());
        in_array('issuedBy', $this->configures) || $this->issuedBy($this->issuer());
        in_array('expiresAt', $this->configures) || $this->lifetime($this->lifetime);

        return $this->builder->getToken($this->signer, InMemory::plainText($this->signingKey()));
    }

    public function __toString(): string
    {
        return $this->getToken()->toString();
    }

    public function expiresAt(DateTimeInterface $expiration): self
    {
        if($expiration instanceof DateTime) {
            $expiration = DateTimeImmutable::createFromMutable($expiration);
        }

        $this->builder->expiresAt($expiration);
        $this->configures[] = "expiresAt";

        return $this;
    }

    public function lifetime(int $seconds): self
    {
        $this->expiresAt(CarbonImmutable::now()->addSeconds($seconds));

        return $this;
    }

    public function withClaims(array $claims = []): self
    {
        foreach ($claims AS $key => $value) {
            $this->builder->withClaim($key, $value);
        }

        return $this;
    }

    public function get(string $id, array $claims = [], int|DateTimeInterface $lifetime = null, string $signingKey = null): string
    {
        return $this
            ->when($signingKey !== null, fn() => $this->signWith($signingKey))
            ->when(is_int($lifetime), fn() => $this->lifetime($lifetime))
            ->when($lifetime instanceof DateTimeInterface, fn() => $this->expiresAt($lifetime))
            ->withClaims($claims)
            ->identifiedBy($id)
            ->getToken()
            ->toString();
    }

    public function __call(string $method, array $parameters): mixed
    {
        $this->configures[] = $method;

        $result = $this->forwardCallTo($this->builder, $method, $parameters);

        return $result instanceof Builder
            ? $this
            : $result;
    }

    public function parse(string $jwt): ParsedToken
    {
        return ParsedToken::fromString($jwt);
    }
}
