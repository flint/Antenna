<?php

namespace Antenna\Tests;

use Antenna\Coder;

class CoderTest extends \PHPUnit_Framework_TestCase
{
    public function testCoding()
    {
        $coder = new Coder('shared_secret');

        // Object is needed as JWT decodes into stdClass.
        $token = (object) [
            'sub' => 'my_subject',
        ];

        $this->assertEquals($token, $coder->decode($coder->encode($token)));
    }
}
