<?php

namespace STS\JWT;

use Carbon\Carbon;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Builder as BaseBuilder;

/**
 *
 */
class Client
{
    /** @var BaseBuilder */
    protected $builder;

    /** @var int */
    protected $lifetime;

    /** @var bool */
    protected $isSigned = false;

    /** @var string */
    protected $defaultSigningKey;

    /** @var string */
    protected $signingKey;

    /** @var null */
    protected $issuedAt;

    /** @var string */
    protected $issuer;

    /** @var string */
    protected $audience;

    /** @var array */
    protected $claims = [];

    /**
     * @param string $signingKey
     * @param int|Carbon $lifetime
     * @param $issuer
     * @param $audience
     */
    public function __construct($signingKey, $lifetime, $issuer, $audience)
    {
        $this->lifetime = $lifetime;
        $this->defaultSigningKey = $signingKey;
        $this->signingKey = $signingKey;

        $this->reset();
        $this->issuer = $issuer;
        $this->audience = $audience;
    }

    /**
     * @return $this
     */
    public function reset()
    {
        $this->builder = new BaseBuilder();
        $this->setLifetime($this->lifetime);
        $this->claims = [];
        $this->signingKey = $this->defaultSigningKey;
        $this->isSigned = false;

        return $this;
    }

    /**
     * @return string
     */
    public function getDefaultAudience()
    {
        return $this->audience;
    }

    /**
     * @return string
     */
    public function getDefaultIssuer()
    {
        return $this->issuer;
    }

    /**
     * @param $signingKey
     *
     * @return $this
     */
    public function setSigningKey($signingKey)
    {
        $this->signingKey = $signingKey;

        return $this;
    }

    /**
     * @return string
     */
    public function getSigningKey()
    {
        return $this->signingKey;
    }

    /**
     * @param Signer $signer
     * @param string $key
     *
     * @return $this
     */
    public function sign(Signer $signer, $key)
    {
        $this->isSigned = true;

        $this->builder->sign($signer, $key);

        return $this;
    }

    /**
     * We want to enforce a couple things before token is generated
     */
    public function getToken()
    {
        // Ensure we have an audience set
        if (!in_array('aud', $this->claims)) {
            $this->builder->setAudience($this->audience);
        }

        // Ensure we have an issuer set
        if (!in_array('iss', $this->claims)) {
            $this->builder->setIssuer($this->issuer);
        }

        // We always sign. Always.
        if (!$this->isSigned) {
            $this->sign(new Sha256(), $this->getSigningKey());
        }

        $token = $this->builder->getToken();

        $this->reset();

        return $token;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->getToken();
    }

    /**
     * @param int|Carbon $lifetime
     *
     * @return $this
     */
    public function setLifetime($lifetime)
    {
        if (is_int($lifetime)) {
            $this->builder->setExpiration(time() + $lifetime);
        }

        if ($lifetime instanceof Carbon) {
            $this->builder->setExpiration($lifetime->timestamp);
        }

        return $this;
    }

    /**
     * @param array $claims
     *
     * @return $this
     */
    public function setClaims(array $claims = [])
    {
        foreach ($claims AS $key => $value) {
            $this->claims[] = $key;
            $this->builder->set($key, $value);
        }

        return $this;
    }

    /**
     * Helper function to quickly generate a simple string token
     *
     * @param string $id
     * @param array $claims
     * @param int|Carbon $lifetime
     * @param string $signingKey
     *
     * @return string
     */
    public function get($id, array $claims = [], $lifetime = null, $signingKey = null)
    {
        if ($signingKey != null) {
            $this->setSigningKey($signingKey);
        }

        return (string)$this
            ->setLifetime($lifetime)
            ->setClaims($claims)
            ->setId($id)
            ->getToken();
    }

    /**
     * @param $audience
     *
     * @return $this
     */
    public function setAudience($audience)
    {
        $this->builder->setAudience($audience);
        $this->claims[] = "aud";

        return $this;
    }

    /**
     * @param $issuer
     *
     * @return $this
     */
    public function setIssuer($issuer)
    {
        $this->builder->setIssuer($issuer);
        $this->claims[] = "iss";

        return $this;
    }

    /**
     * @param $method
     * @param $parameters
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        $result = call_user_func_array([$this->builder, $method], $parameters);

        return $result instanceof BaseBuilder
            ? $this
            : $result;
    }

    /**
     * @param $jwt
     *
     * @return ParsedToken
     */
    public function parse($jwt)
    {
        return ParsedToken::fromString($jwt);
    }
}