<?php

namespace Antenna;

use DateTimeInterface;

class WebToken
{
    private $subject;
    private $issuedAt;
    private $expireAt;

    public function __construct($subject, DateTimeInterface $issuedAt, DateTimeInterface $expireAt)
    {
        $this->subject = $subject;
        $this->issuedAt = $issuedAt;
        $this->expireAt = $expireAt;
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
}
