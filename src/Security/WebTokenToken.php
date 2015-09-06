<?php

/*
 * This file is part of the Antenna package.
 *
 * (c) 2015 Henrik Bjornskov <henrik@bjrnskov.dk>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


namespace Antenna\Security;

use Antenna\WebToken;

class WebTokenToken extends \Symfony\Component\Security\Core\Authentication\Token\AbstractToken
{
    private $providerKey;
    private $webToken;

    public function __construct($providerKey, WebToken $webToken, array $roles = [])
    {
        parent::__construct($roles);

        $this->providerKey = $providerKey;
        $this->webToken = $webToken;
    }

    public function setUser($user)
    {
        parent::setUser($user);

        return $this;
    }

    public function setAuthenticated($authenticated)
    {
        parent::setAuthenticated($authenticated);

        return $this;
    }

    public function getWebToken()
    {
        return $this->webToken;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function getCredentials()
    {
        return '';
    }

    public function serialize()
    {
        return serialize([
            $this->providerKey,
            $this->webToken,
            parent::serialize(),
        ]);
    }

    public function unserialize($serialized)
    {
        list($this->providerKey, $this->webToken, $previous) = unserialize($serialized);

        parent::unserialize($previous);
    }
}
