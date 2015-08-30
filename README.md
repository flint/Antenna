Antenna
=======

[![Build Status](https://travis-ci.org/henrikbjorn/Antenna.svg?branch=master)](https://travis-ci.org/henrikbjorn/Antenna)

Antenna is a small library that helps integrating JWT (JSON Web Token) for projects using
the Symfony Security Component.

In order to use this library you need to set up two authenticators in your firewall.

The first is `UsernamePasswordAuthenticator` which uses the security flow to authenticate through and
then "hijack" the request by rendering a body with a token `{ "token" : "json web token here" }`.

The second uses the `Authorization: Bearer <json web token>` header style to authenticate your
users by validating the JWT.

Using Symfony Standard it would look something like:

``` yaml
services:
    antenna.coder:
        class: Antenna\Coder
        arguments: ['shared-secret']

    antenna.username_password_authenticator:
        class: Antenna\Security\UsernamePasswordAuthenticator
        arguments: [@security.user_checker, @security.encoder_factory, @antenna.coder]

    antenna.token_authenticator:
        class: Antenna\Security\TokenAuthenticator
        arguments: [@security.user_checker, @antenna.coder]

security:
    providers:
        in_memory:
            memory:
                users:
                    henrikbjorn:
                        password: my-unique-password
                        roles: 'ROLE_USER'

    firewalls:
        token_exchange:
            pattern: ^/auth
            simple-preauth:
                provider: in_memory
                authenticator: antenna.username_password_authenticator
        web_token:
            pattern: ^/api
            simple-preauth:
                provider: in_memory
                authenticator: antenna.token_authenticator
```
