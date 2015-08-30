Antenna
=======

Recentry i had to implement authentication in an AngularJS application. For this pupose i found
https://github.com/sahat/satellizer which supports different flows of authentication, one of these
is username/password through JSON Web Token (JWT).

This small library combines firebase/php-jwt and two custom Symfony Security SimplePreAuthenticators
in order to have a simple flow.

`TokenExchangeAuthenticator` only purpose is to take the username / password provided in a JSON request and return a
valid JWT token. Depending on the way it have been setup.

`TokenAuthenticator` assumes a `Authorization: Bearer my-token` header is present and will use a `TokenUserProvider`
implementation to authenticate the User.
