<?php

namespace STS\JWT\Facades;

use Illuminate\Support\Facades\Facade;
use STS\JWT\Client;

class JWT extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return Client::class;
    }
}