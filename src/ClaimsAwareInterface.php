<?php

namespace Antenna;

interface ClaimsAwareInterface
{
    /**
     * @return [string]mixed a key/value array of additional claims
     */
    public function getClaims();
}
