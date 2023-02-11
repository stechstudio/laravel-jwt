<?php

namespace STS\JWT\Facades;

use Illuminate\Support\Facades\Facade;
use STS\JWT\Client;

/**
 * @mixin Client
 */
class JWT extends Facade
{
    protected static function getFacadeAccessor()
    {
        return Client::class;
    }
}