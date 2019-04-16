<?php

namespace STS\JWT\Exceptions;

use Lcobucci\JWT\Token;

class JwtExpiredException extends \Exception
{
    /** @var Token */
    protected $token;

    /**
     * @param $token
     */
    public function __construct($token)
    {
        parent::__construct("Token has expired");
        $this->token = $token;
    }
}