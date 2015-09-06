<?php

namespace Antenna\Tests;

use Antenna\Coder;
use Antenna\WebToken;

class CoderTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->coder = new Coder('shared_secret');
    }

    public function testCoding()
    {
        $utc = new \DateTimeZone('UTC');
        $issuedAt = date_create_immutable('now');
        $expireAt = date_create_immutable('+1 year');

        $webToken = $this->coder->decode(
            $this->coder->encode(
                new WebToken('my_subject', $issuedAt, $expireAt)
            )
        );

        $this->assertEquals('my_subject', $webToken->getSubject());
        $this->assertEquals($issuedAt->getTimestamp(), $webToken->getIssuedAt()->getTimestamp());
        $this->assertEquals($expireAt->getTimestamp(), $webToken->getExpireAt()->getTimestamp());
    }

    public function testClaims()
    {
        $claims = [
            'administrator' => 1,
            'roles' => ['ROLE_USER', 'ROLE_SUPER_ADMIN'],
        ];

        $webToken = $this->coder->decode(
            $this->coder->encode(
                new WebToken('my_subject', date_create(), date_create('+1 year'), $claims)
            )
        );

        $this->assertEquals($claims, $webToken->all());
    }
}
