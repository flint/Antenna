<?php

namespace Antenna;

use Firebase\JWT\JWT;
use DateTimeImmutable;
use DateTimeZone;

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
        $payload = [
            'sub' => $webToken->getSubject(),
            'iat' => $webToken->getIssuedAt()->getTimestamp(),
            'exp' => $webToken->getExpireAt()->getTimestamp(),
        ];

        return JWT::encode($payload, $this->secret, $this->algoritm);
    }

    /**
     * @param string $encoded
     * @return WebToken
     */
    public function decode($encoded)
    {
        $payload = (array) JWT::decode($encoded, $this->secret, [$this->algoritm]) + [
            'sub' => null,
            'iat' => null,
            'exp' => null,
        ];

        $expireAt = new DateTimeImmutable('@' . $payload['exp']);
        $issuedAt = new DateTimeImmutable('@' . $payload['iat']);

        return new WebToken($payload['sub'], $issuedAt, $expireAt);
    }
}
