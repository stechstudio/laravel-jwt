<?php

class ValidationTest extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app)
    {
        return [\STS\JWT\JWTServiceProvider::class];
    }

    protected function getPackageAliases($app)
    {
        return [
            'JWT' => \STS\JWT\JWTFacade::class
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set([
            'jwt.key'      => 'thisissigningkey',
            'jwt.audience' => 'myappaud',
            'jwt.issuer'   => 'myappiss'
        ]);
    }

    public function testEmptyToken()
    {
        $this->expectExceptionMessage("The JWT string must have two dots");
        JWT::parse("");
    }

    public function testBadToken()
    {
        $this->expectExceptionMessage("The JWT string must have two dots");
        JWT::parse("foobar");
    }

    public function testBorkedToken()
    {
        $this->expectExceptionMessage("Error while decoding to JSON");
        JWT::parse("firstpart.secondpart.thirdpart");
    }

    public function testParseGoodToken()
    {
        $jwt = JWT::get('test-id');
        $token = JWT::parse($jwt);

        $this->assertInstanceOf(\STS\JWT\ParsedToken::class, $token);
        $this->assertTrue($token->isValid('test-id'));
    }

    public function testExpiredToken()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get('test-id', [], -1));

        $this->assertTrue($token->isExpired());

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtExpiredException::class);
        $this->expectExceptionMessage("Token has expired");
        $token->validate('test-id');
    }

    public function testIdMismatch()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get('test-id'));

        $this->assertFalse($token->isValid('different-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("JWT claim [jti] is invalid");
        $token->validate('different-id');
    }

    public function testInvalidAudienceMismatch()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::setAudience("foobar")->get('test-id'));

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("JWT claim [aud] is invalid");
        $token->validate('test-id');
    }

    public function testInvalidSignature()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::setSigningKey("foobar")->get('test-id'));

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("JWT signature is invalid");
        $token->validate('test-id');
    }

    public function testPassAlternateSigningKey()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::setSigningKey("foobar")->get('test-id'));

        $this->assertTrue($token->isValid('test-id', "foobar"));
    }

    public function testInvalidPayload()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::setSubject("foobar")->get('test-id'));

        // initially this is find
        $this->assertTrue($token->isValid('test-id'));

        // build a custom set of validation data requirements
        $data = new \Lcobucci\JWT\ValidationData();
        $data->setId('test-id');
        $data->setSubject("baz");

        $this->assertFalse($token->isValid($data));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("JWT claim [sub] is invalid");
        $token->validate($data);
    }

    // When we create a token with our own JWT client it enforces a few things. Let's now create one with the Builder
    // directly, NOT adding the attributes we normally enforce, and ensure they are caught on the validation side.

    public function testMissingExpiration()
    {
        // Plain token with nothing supplied
        $jwt = (string) (new \Lcobucci\JWT\Builder())->getToken();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("Token expiration is missing");
        $token->validate('test-id');
    }

    public function testMissingID()
    {
        $jwt = (string) (new \Lcobucci\JWT\Builder())
            ->setExpiration(time() + 60)
            ->getToken();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("Token ID is missing");
        $token->validate('test-id');
    }

    public function testMissingAudience()
    {
        $jwt = (string) (new \Lcobucci\JWT\Builder())
            ->setExpiration(time() + 60)
            ->setId('test-id')
            ->sign(new \Lcobucci\JWT\Signer\Hmac\Sha256(), 'thisissigningkey')
            ->getToken();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(\STS\JWT\Exceptions\JwtValidationException::class);
        $this->expectExceptionMessage("Token audience is missing");
        $token->validate('test-id');
    }

    public function testNoAudienceValidation()
    {
        config(['jwt.validate.audience' => false]);

        $jwt = (string) (new \Lcobucci\JWT\Builder())
            ->setExpiration(time() + 60)
            ->setId('test-id')
            ->sign(new \Lcobucci\JWT\Signer\Hmac\Sha256(), 'thisissigningkey')
            ->getToken();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $token->validate('test-id');
        $this->assertTrue($token->isValid('test-id'));
    }

    public function testMissingSignature()
    {
        $jwt = (string) (new \Lcobucci\JWT\Builder())
            ->setExpiration(time() + 60)
            ->setId('test-id')
            ->setAudience('myappaud')
            ->getToken();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(BadMethodCallException::class);
        $this->expectExceptionMessage("This token is not signed");
        $token->validate('test-id');
    }
}