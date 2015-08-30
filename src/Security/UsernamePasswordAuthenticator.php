<?php

namespace Antenna\Security;

use Antenna\Coder;
use Antenna\WebToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\UnsupportedMediaTypeHttpException;

/**
 * Duplicate implementation of the UsernamePasswordForm authentication that
 * is found in Symfony.
 *
 * This one requires a json post payload, also it will force a response containing
 * a json web token.
 */
class UsernamePasswordAuthenticator implements
    SimplePreAuthenticatorInterface,
    AuthenticationFailureHandlerInterface,
    AuthenticationSuccessHandlerInterface
{
    private $userChecker;
    private $encoderFactory;
    private $coder;

    /**
     * @param UserCheckerInterface    $userChecker
     * @param EncoderFactoryInterface $encoderFactory
     * @param Coder                   $coder
     */
    public function __construct(
        UserCheckerInterface $userChecker,
        EncoderFactoryInterface $encoderFactory,
        Coder $coder
    ) {
        $this->userChecker = $userChecker;
        $this->encoderFactory = $encoderFactory;
        $this->coder = $coder;
    }

    /**
     * {@inheritdoc}
     */
    public function createToken(Request $request, $providerKey)
    {
        if (!$request->isMethod('POST')) {
            throw new MethodNotAllowedHttpException(['POST']);
        }

        if ($request->getContentType() != 'json') {
            throw new UnsupportedMediaTypeHttpException('Content-Type must be "application/json".');
        }

        $body = json_decode($request->getContent(), true);

        list($username, $password) = array_values($body + ['username' => null, 'password' => null]);

        return new UsernamePasswordToken($username, $password, $providerKey);
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        $user = $userProvider->loadUserByUsername($token->getUsername());

        $this->userChecker->checkPreAuth($user);

        $encoder = $this->encoderFactory->getEncoder($user);

        if (!$encoder->isPasswordValid($user->getPassword(), $token->getCredentials(), $user->getSalt())) {
            throw new BadCredentialsException('The presented password is invalid.');
        }

        $this->userChecker->checkPostAuth($user);

        return new UsernamePasswordToken($user, $token->getCredentials(), $providerKey, $user->getRoles());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        if (!$token instanceof UsernamePasswordToken) {
            return false;
        }

        return $providerKey == $token->getProviderKey();
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new Response($exception->getMessage(), 401);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $webToken = new WebToken($token->getUsername(), date_create_immutable(), date_create_immutable('+7 days'));

        return new JsonResponse([
            'token' => $this->coder->encode($webToken)
        ]);
    }
}
