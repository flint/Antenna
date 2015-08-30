<?php

namespace Antenna\Tests;

use Antenna\Token;
use Symfony\Component\Security\Core\User\User;

class TokenTest extends \PHPUnit_Framework_TestCase
{
    public function testToken()
    {
        $token = new Token('my_provider_key', ['my-token' => true]);

        $user = new User('my_username', 'my_password');

        $this->assertEquals('my_provider_key', $token->getProviderKey());
        $this->assertEquals(['my-token' => true], $token->getToken());
        $this->assertEquals($token, unserialize(serialize($token)));
        $this->assertEquals('', $token->getCredentials());
        $this->assertSame($token, $token->setUser($user));
    }
}
