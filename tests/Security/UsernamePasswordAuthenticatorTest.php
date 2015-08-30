<?php

namespace Antenna\Tests\Security;

use Antenna\Coder;
use Antenna\Security\UsernamePasswordAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;

class UsernamePasswordAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $encoder = new PlaintextPasswordEncoder();
        $userChecker = new UserChecker();
        $coder = new Coder('my_secret');

        $encoderFactory = new EncoderFactory([
            'Symfony\Component\Security\Core\User\UserInterface' => $encoder,
        ]);

        $this->userProvider = new InMemoryUserProvider([
            'my_username' => ['password' => 'my_password', 'roles' => ['ROLE_USER']],
        ]);

        $this->authenticator = new UsernamePasswordAuthenticator($userChecker, $encoderFactory, $coder);
    }

    public function testCreateTokenNotApplicationJson()
    {
        $request = Request::create('/', 'POST');

        $this->setExpectedException('Symfony\Component\HttpKernel\Exception\UnsupportedMediaTypeHttpException');

        $this->authenticator->createToken($request, 'my_provider');
    }

    public function testCreateTokenNotPost()
    {
        $request = Request::create('/');

        $this->setExpectedException('Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException');

        $this->authenticator->createToken($request, 'my_provider');
    }

    public function testCreateToken()
    {
        $request = Request::create('/', 'POST', [], [], [], [], json_encode([
            'username' => 'my_username',
            'password' => 'my_credential',
        ]));

        $request->headers->set('Content-Type', 'application/json');

        $token = $this->authenticator->createToken($request, 'my_provider');

        $this->assertInstanceOf('Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken', $token);
        $this->assertEquals('my_username', $token->getUser());
        $this->assertEquals('my_credential', $token->getCredentials());
        $this->assertEquals('my_provider', $token->getProviderKey());
        $this->assertFalse($token->isAuthenticated());
    }

    public function testAuthenticateToken()
    {
        $token = new UsernamePasswordToken('my_username', 'my_password', 'my_provider');

        $token = $this->authenticator->authenticateToken($token, $this->userProvider, 'my_provider');

        $this->assertInstanceOf('Symfony\Component\Security\Core\User\UserInterface', $token->getUser());
        $this->assertTrue($token->isAuthenticated());
    }

    public function testAuthenticateTokenInvalidCredentials() {
        $this->setExpectedException('Symfony\Component\Security\Core\Exception\BadCredentialsException');

        $token = new UsernamePasswordToken('my_username', 'my_invalid_password', 'my_provider');

        $this->authenticator->authenticateToken($token, $this->userProvider, 'my_provider');
    }

    public function testSupportsToken()
    {
        $token = new UsernamePasswordToken('my_username', 'my_credential', 'my_provider');

        $this->assertTrue($this->authenticator->supportsToken($token, 'my_provider'));
        $this->assertFalse($this->authenticator->supportsToken($token, 'not_my_provider'));

        $token = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $this->assertFalse($this->authenticator->supportsToken($token, 'my_provider'));
        $this->assertFalse($this->authenticator->supportsToken($token, 'not_my_provider'));
    }
}
