<?php

/*
 * This file is part of the Antenna package.
 *
 * (c) 2015 Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


namespace Antenna\Tests\Security;

use Antenna\Security\WebTokenToken;
use Antenna\WebToken;
use Symfony\Component\Security\Core\User\User;

class WebTokenTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testToken()
    {
        $webToken = new WebToken('my_username', date_create(), date_create());

        $token = new WebTokenToken('my_provider_key', $webToken);
        $user = new User('my_username', 'my_password');

        $this->assertEquals('my_provider_key', $token->getProviderKey());
        $this->assertEquals($webToken, $token->getWebToken());

        $this->assertEquals($token, unserialize(serialize($token)));
        $this->assertEquals('', $token->getCredentials());
        $this->assertSame($token, $token->setUser($user));
    }
}
