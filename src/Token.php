<?php

namespace Antenna;

class Token extends \Symfony\Component\Security\Core\Authentication\Token\AbstractToken
{
    private $providerKey;
    private $token;

    public function __construct($providerKey, $token, array $roles = [])
    {
        parent::__construct($roles);

        $this->providerKey = $providerKey;
        $this->token = $token;
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

    public function getToken()
    {
        return $this->token;
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
            $this->token,
            parent::serialize(),
        ]);
    }

    public function unserialize($serialized)
    {
        list($this->providerKey, $this->token, $previous) = unserialize($serialized);

        parent::unserialize($previous);
    }
}
