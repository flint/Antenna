Antenna
=======

[![Build Status](https://travis-ci.org/flint/Antenna.svg?branch=master)](https://travis-ci.org/flint/Antenna)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/flint/Antenna/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/flint/Antenna/?branch=master)

Antenna is a small library that helps integrating JWT (JSON Web Token) for projects using
the Symfony Security Component.

In order to use this library you need to set up two authenticators in your firewall.

The first is `UsernamePasswordAuthenticator` which uses the security flow to authenticate through and
then "hijack" the request by rendering a body with a token `{ "token" : "json web token here" }`.

The second uses the `Authorization: Bearer <json web token>` header style to authenticate your
users by validating the JWT.

If you use Symfony Full Stack there is a [AntennaBundle](https://github.com/flint/AntennaBundle) which provides a simple integration.

Also look in the bundle if you want to know how to integrate with other libraries that use Symfony Security.
