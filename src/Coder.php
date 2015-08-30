<?php

namespace Antenna;

use Firebase\JWT\JWT;

class Coder
{
    private $secret;
    private $algoritm = 'HS256';

    public function __construct($secret)
    {
        $this->secret = $secret;
    }

    public function encode($token)
    {
        return JWT::encode($token, $this->secret, $this->algoritm);
    }

    public function decode($token)
    {
        return JWT::decode($token, $this->secret, [$this->algoritm]);
    }
}
