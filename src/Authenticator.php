<?php

namespace Antenna;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;

class Authenticator implements SimplePreAuthenticatorInterface, AuthenticationFailureHandlerInterface
{
    private $userChecker;
    private $coder;

    /**
     * @param UserCheckerInterface $userChecker
     * @param Coder                $coder
     */
    public function __construct(UserCheckerInterface $userChecker, Coder $coder)
    {
        $this->userChecker = $userChecker;
        $this->coder = $coder;
    }

    /**
     * Look at the request and see if the is a header with the token. If we find
     * the token, then create a PreAuthenticatedToken and let authenticateToken()
     * try and authenticate it.
     * 
     * {@inheritdoc}
     */
    public function createToken(Request $request, $providerKey)
    {
        $bearer = $request->headers->get('Authorization');

        if (!$bearer) {
            throw new BadCredentialsException('Authorization was not found in headers.');
        }

        if (0 !== strpos($bearer, 'Bearer')) {
            throw new BadCredentialsException('Authorization was not of type Bearer');
        }

        return new Token($providerKey, $this->coder->decode(substr($bearer, 7)));
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        // I really want an actual Token object instead of stdClass implementation
        $token = $token->getToken();

        $user = $userProvider->loadUserByUsername($token->sub);

        $this->userChecker->checkPreAuth($user);
        $this->userChecker->checkPostAuth($user);

        return (new Token($providerKey, $token, $user->getRoles()))
            ->setAuthenticated(true)
            ->setUser($user)
        ;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        if ($token instanceof Token) {
            return $providerKey == $token->getProviderKey();
        }

        return false;
    }

    /**
     * When we cannot authenticate we want a 401 error as the Angular application
     * looks at the status codes in order to invalidate requests.
     *
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new Response($exception->getMessage(), 401);
    }
}
