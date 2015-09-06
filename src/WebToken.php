<?php

/*
 * This file is part of the Antenna package.
 *
 * (c) 2015 Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


namespace Antenna;

use DateTimeInterface;

/**
 * Represents part of a Json Web Token.
 *
 * Its main relation is "claims" and as such, the methods for interacting
 * with these follow the Symfony Convention http://symfony.com/doc/current/contributing/code/conventions.html#method-names
 *
 * Not this is an immutable class.
 */
class WebToken
{
    private $subject;
    private $issuedAt;
    private $expireAt;
    private $claims = [];

    /**
     * @param string            $subject  The sub (subject) claim identifies the principal that is the subject of the JWT.
     * @param DateTimeInterface $issuedAt The iat (issued at) claim identifies the time at which the JWT was issued.
     * @param DateTimeInterface $expireAt The exp (expiration time) claim identifies the expiration time.
     * @param [string]mixed Additional claims that is not required.
     */
    public function __construct($subject, DateTimeInterface $issuedAt, DateTimeInterface $expireAt, $claims = [])
    {
        $this->subject = $subject;
        $this->issuedAt = $issuedAt;
        $this->expireAt = $expireAt;
        $this->claims = $claims;
    }

    public function getSubject()
    {
        return $this->subject;
    }

    public function getIssuedAt()
    {
        return $this->issuedAt;
    }

    public function getExpireAt()
    {
        return $this->expireAt;
    }

    public function all()
    {
        return $this->claims;
    }

    public function keys()
    {
        return array_keys($this->claims);
    }

    public function has($claim)
    {
        return array_key_exists($claim, $this->claims);
    }

    public function get($claim, $default = null)
    {
        return $this->has($claim) ? $this->claims[$claim] : $default;
    }
}
