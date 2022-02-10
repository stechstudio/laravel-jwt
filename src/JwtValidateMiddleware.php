<?php

namespace STS\JWT;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class JwtValidateMiddleware
{
    /**
     * @param Request $request
     * @param Closure $next
     * @param null $id
     *
     * @return mixed
     * @throws Exceptions\JwtExpiredException
     * @throws Exceptions\JwtValidationException
     */
    public function handle(Request $request, Closure $next, $id = null)
    {
        if ($id === null) {
            $id = $request->route()->getName();
        }

        $token = ParsedToken::fromString(
            $this->findJWT($request)
        )->validate($id);

        $request->setToken($token);

        if(config('jwt.merge')) {
            $request->merge($token->getPayload());
        }

        return $next($request);
    }

    /**
     * The JWT can be provided as a route parameter, request variable, or authorization header
     * @param Request $request
     *
     * @return string
     */
    public function findJWT(Request $request)
    {
        // Laravel route parameter
        if ($request->route('token')) {
            return $request->route('token');
        }
        if ($request->route('jwt')) {
            return $request->route('jwt');
        }

        // Request variable
        if ($request->has('token')) {
            return $request->get('token');
        }
        if ($request->has('jwt')) {
            return $request->get('jwt');
        }

        // Authorization header
        if ($request->hasHeader('Authorization')) {
            return $this->parseAuthorizationHeader($request->header('Authorization'));
        }

        throw new UnauthorizedHttpException("","Token not provided");
    }

    /**
     * @param $header
     *
     * @return string
     */
    protected function parseAuthorizationHeader($header)
    {
        if (strpos($header, "Basic") === 0) {
            // This is being provided as basic auth, which means the token is base64 encoded
            list($tokenString) = sscanf($header, "Basic %s");
            // The decoded auth string will have a dummy username, a colon, and then the password (token)
            $decodedParts = explode(":", base64_decode($tokenString));

            return $decodedParts[1];
        }

        // Otherwise we expect the token to be specific directly (not encoded) with the "Token" label
        list($tokenString) = sscanf($header, "Token %s");

        return $tokenString;
    }
}