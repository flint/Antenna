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

interface ClaimsAwareInterface
{
    /**
     * @return [string]mixed a key/value array of additional claims
     */
    public function getClaims();
}
