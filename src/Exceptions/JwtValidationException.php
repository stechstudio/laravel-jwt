<?php

namespace STS\JWT\Exceptions;

use Lcobucci\JWT\Token;

class JwtValidationException extends \Exception
{
    /** @var Token */
    protected $token;

    /**
     * @param $message
     * @param $token
     */
    public function __construct($message, $token)
    {
        parent::__construct($message);
        $this->token = $token;
    }
}