<?php

namespace Antenna\Tests;

use Antenna\Coder;
use Antenna\WebToken;

class CoderTest extends \PHPUnit_Framework_TestCase
{
    public function testCoding()
    {
        $coder = new Coder('shared_secret');

        $utc = new \DateTimeZone('UTC');
        $issuedAt = date_create_immutable('now');
        $expireAt = date_create_immutable('+1 year');

        $webToken = $coder->decode($coder->encode(
            new WebToken('my_subject', $issuedAt, $expireAt)
        ));

        $this->assertEquals('my_subject', $webToken->getSubject());
        $this->assertEquals($issuedAt->getTimestamp(), $webToken->getIssuedAt()->getTimestamp());
        $this->assertEquals($expireAt->getTimestamp(), $webToken->getExpireAt()->getTimestamp());
    }
}
