<?php
return [
    // Look for a dedicated signing key, fall back to app key
    'key' => env('JWT_SIGNING_KEY', env('APP_KEY')),

    // Default lifetime in seconds
    'lifetime' => env('JWT_LIFETIME', 600),

    // Default audience name for our own app
    'audience' => env('JWT_AUDIENCE', strtolower(env('APP_NAME'))),

    // Default issuer name for our own app
    'issuer' => env('JWT_ISSUER', strtolower(env('APP_NAME'))),

    'merge' => env('JWT_MERGE_PAYLOAD', true),

    'validate' => [
        // If you really need to avoid automatic audience validation
        'audience' => env('JWT_VALIDATE_AUDIENCE', true),
    ]
];