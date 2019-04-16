<?php
return [
    // Look for a dedicated signing key, fall back to app key
    'key' => env('JWT_SIGNING_KEY', env('APP_KEY')),

    // Default lifetime in seconds
    'lifetime' => 600,

    // Default audience name for our own app
    'audience' => env('JWT_AUDIENCE', strtolower(env('APP_NAME'))),

    // Default issuer name for our own app
    'issuer' => env('JWT_ISSUER', strtolower(env('APP_NAME'))),
];