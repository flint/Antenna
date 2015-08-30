<?php

namespace Antenna\Tests\Security;

use Antenna\Security\Authenticator;
use Antenna\Security\Token;
use Antenna\WebToken;
use Antenna\Coder;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;

class AuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $userChecker = new UserChecker();

        $this->userProvider = new InMemoryUserProvider([
            'my_username' => [],
        ]);

        $this->coder = new Coder('my_secret');
        $this->authenticator = new Authenticator($userChecker, $this->coder);
    }

    public function testAuthenticationFailedHandler()
    {
        $this->assertInstanceOf('Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface', $this->authenticator);

        $exception = new AuthenticationException('My Custom Message');
        $request = new Request();

        $response = $this->authenticator->onAuthenticationFailure($request, $exception);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('My Custom Message', $response->getContent());
    }

    public function testSupportsToken()
    {
        $invalidToken = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $this->assertFalse($this->authenticator->supportsToken($invalidToken, 'my_provider'));

        $token = new Token('my_provider', []);

        $this->assertFalse($this->authenticator->supportsToken($token, 'invalid_provider'));
        $this->assertTrue($this->authenticator->supportsToken($token, 'my_provider'));
    }

    public function testCreateTokenNoHeader()
    {
        $this->setExpectedException(
            'Symfony\Component\Security\Core\Exception\BadCredentialsException',
            'Authorization was not found in headers.'
        );

        $request = new Request();

        $this->authenticator->createToken($request, 'my_provider');
    }

    public function testCreateTokenNotBearer()
    {
        $this->setExpectedException(
            'Symfony\Component\Security\Core\Exception\BadCredentialsException',
            'Authorization was not of type Bearer'
        );

        $request = new Request();
        $request->headers->set('Authorization', 'Invalid');

        $this->authenticator->createToken($request, 'my_provider');
    }

    public function testCreateToken()
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJteV91c2VybmFtZSIsImlhdCI6MTQ0MDk0Njg0NSwiZXhwIjoxNTA0MTA1MjQ1fQ.D3UaQO3Bq-Oezp-_6EK2GcpUi3iS858GvbmoXBS4ZCs');

        $token = $this->authenticator->createToken($request, 'my_provider');

        $this->assertInstanceOf('Antenna\WebToken', $token->getToken());
        $this->assertEquals('my_provider', $token->getProviderKey());
    }

    public function testAuthenticateToken()
    {
        $token = new Token('my_provider', (object) [
            'exp' => strtotime('+2 years'),
            'sub' => 'my_username',
        ]);

        $token = $this->authenticator->authenticateToken($token, $this->userProvider, 'my_provider');

        $this->assertEquals($token->getUser(), $this->userProvider->loadUserByUsername('my_username'));
        $this->assertTrue($token->isAuthenticated());
    }
}
