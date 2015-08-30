<?php

namespace Antenna;

interface TokenUserProviderInterface
{
    /**
     * @param mixed $token
     *
     * @throws Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     *
     * @return Symfony\Component\Security\Core\User\UserInterface
     */
    public function loadUserByToken($token);
}
