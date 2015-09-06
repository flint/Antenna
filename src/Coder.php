<?php

namespace Antenna;

use Firebase\JWT\JWT;
use DateTimeImmutable;

class Coder
{
    private $secret;
    private $algoritm = 'HS256';

    public function __construct($secret)
    {
        $this->secret = $secret;
    }

    public function encode(WebToken $webToken)
    {
        $payload = $webToken->all() + [
            'sub' => $webToken->getSubject(),
            'iat' => $webToken->getIssuedAt()->getTimestamp(),
            'exp' => $webToken->getExpireAt()->getTimestamp(),
        ];

        return JWT::encode($payload, $this->secret, $this->algoritm);
    }

    /**
     * @param string $encoded
     *
     * @return WebToken
     */
    public function decode($encoded)
    {
        $defaults = [
            'sub' => null,
            'iat' => null,
            'exp' => null,
        ];

        $payload = (array) JWT::decode($encoded, $this->secret, [$this->algoritm]) + $defaults;

        $claims = array_diff_key($payload, $defaults);

        $expireAt = new DateTimeImmutable('@'.$payload['exp']);
        $issuedAt = new DateTimeImmutable('@'.$payload['iat']);

        return new WebToken($payload['sub'], $issuedAt, $expireAt, $claims);
    }
}
