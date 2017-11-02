'use strict';

module.exports = require('./src/AuthRoute');

module.exports.Error = require('./src/AuthRouteError');


const authenticators = require('./src/authenticators');

module.exports.PasswordAuthenticator = authenticators.PasswordAuthenticator;
module.exports.ClientCredentialsAuthenticator = authenticators.ClientCredentialsAuthenticator;
