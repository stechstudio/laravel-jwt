<?php

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Validation\ConstraintViolation;
use STS\JWT\Exceptions\InvalidAudience;
use STS\JWT\Exceptions\InvalidID;
use STS\JWT\Exceptions\InvalidSignature;
use STS\JWT\Exceptions\TokenExpired;
use STS\JWT\Facades\JWT;

class ValidationTest extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app)
    {
        return [\STS\JWT\JWTServiceProvider::class];
    }

    protected function getPackageAliases($app)
    {
        return [
            'JWT' => \STS\JWT\Facades\JWT::class
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set([
            'jwt.key'      => 'thisissigningkeythisissigningkey',
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
        $this->expectExceptionMessage("Error while decoding from Base64Url, invalid base64 characters detected");
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

        $this->expectException(TokenExpired::class);
        $this->expectExceptionMessage("The token is expired");
        $token->validate('test-id');
    }

    public function testIdMismatch()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::get('test-id'));

        $this->assertFalse($token->isValid('different-id'));

        $this->expectException(InvalidID::class);
        $this->expectExceptionMessage("The token is not identified with the expected ID");
        $token->validate('different-id');
    }

    public function testInvalidAudienceMismatch()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::permittedFor("foobar")->get('test-id'));

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(InvalidAudience::class);
        $this->expectExceptionMessage("The token is not allowed to be used by this audience");
        $token->validate('test-id');
    }

    public function testInvalidSignature()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::signWith("foobarfoobarfoobarfoobarfoobar!!")->get('test-id'));

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(InvalidSignature::class);
        $this->expectExceptionMessage("Token signature mismatch");
        $token->validate('test-id');
    }

    public function testPassAlternateSigningKey()
    {
        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse(JWT::signWith("foobarfoobarfoobarfoobarfoobar!!")->get('test-id'));

        $this->assertTrue($token->isValid('test-id', "foobarfoobarfoobarfoobarfoobar!!"));
    }

    // When we create a token with our own JWT client it enforces a few things. Let's now create one with the Builder
    // directly, NOT adding the attributes we normally enforce, and ensure they are caught on the validation side.

    public function testMissingAudience()
    {
        // Plain token with nothing supplied
        $jwt = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->getToken(new Sha256(), InMemory::plainText('thisissigningkeythisissigningkey'))->toString();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(InvalidAudience::class);
        $this->expectExceptionMessage("The token is not allowed to be used by this audience");
        $token->validate('test-id');
    }

    public function testMissingID()
    {
        $jwt = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->permittedFor('myappaud')
            ->getToken(new Sha256(), InMemory::plainText('thisissigningkeythisissigningkey'))->toString();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $this->assertFalse($token->isValid('test-id'));

        $this->expectException(InvalidID::class);
        $this->expectExceptionMessage("The token is not identified with the expected ID");
        $token->validate('test-id');
    }

    public function testNoAudienceValidation()
    {
        config(['jwt.validate.audience' => false]);

        $jwt = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->identifiedBy('test-id')
            ->getToken(new Sha256(), InMemory::plainText('thisissigningkeythisissigningkey'))->toString();

        /** @var \STS\JWT\ParsedToken $token */
        $token = JWT::parse($jwt);

        $token->validate('test-id');
        $this->assertTrue($token->isValid('test-id'));
    }
}