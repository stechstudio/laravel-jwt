<?php

if (!function_exists('token')) {
    /**
     * Helper method to quickly generate a JWT
     *
     * @param string $id
     * @param array $claims
     * @param int|\Carbon\Carbon $lifetime
     * @param string $signingKey
     *
     * @return string|\STS\JWT\Client
     */
    function token($id = null, array $claims = [], $lifetime = null, $signingKey = null)
    {
        /** @var \STS\JWT\Client $builder */
        $builder = resolve(\STS\JWT\Client::class);

        if ($signingKey != null) {
            $builder->setSigningKey($signingKey);
        }

        if ($id === null) {
            return $builder;
        }

        return $builder->get($id, $claims, $lifetime);
    }
}