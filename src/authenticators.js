'use string';

function fetchField(req, field){
	if (req.method == 'GET'){
		return req.query[field];
	}else if(req.method == 'POST'){
		return req.body[field];
	}
	return undefined;
}

const AuthRouteError = require('./AuthRouteError');

/**
 *	Implement Resource Owner Password Credentials Grant
 *	grant_type should be 'password'
 * 	@see https://tools.ietf.org/html/rfc6749#page-37
 */
module.exports.PasswordAuthenticator = class PasswordAuthenticator{

	constructor({ usernameField = 'username', passwordField = 'password', passReq = false } = {}, verify){
		this._usernameField = usernameField;
		this._passwordField = passwordField;
		this._passReq = passReq;
		if (typeof verify !== 'function') throw new Error('YOU must provide a valid verify function.');
		this._verify = verify;
	}

	async authenticate(req){
		const username = fetchField(req, this._usernameField);
		const password = fetchField(req, this._passwordField);

		if (!username || !password) throw new AuthRouteError(AuthRouteError.ERROR_CODES.INVALID_GRANT);

		if (this._passReq) return await this._verify(req, username, password);
		else return await this._verify(username, password);
	}
 }

/**
 *	Implement Client Credentials Grant
 *	This version make use of client_id and client_secred
 *	Other version can be defined
 *	grant_type should be 'client_credentials'
 * 	@see https://tools.ietf.org/html/rfc6749#section-4.4
 */
module.exports.ClientCredentialsAuthenticator = class ClientCredentialsAuthenticator{

	constructor({ clientIdField = 'client_id', clientSecretField = 'client_secret', passReq = false } = {}, verify){
		this._clientIdField = clientIdField;
		this._clientSecretField = clientSecretField;
		this._passReq = passReq;
		if (typeof verify !== 'function') throw new Error('you MUST provide a valid verify function.');
		this._verify = verify;
	}

	async authenticate(req){
		const clientId = fetchField(req, this._clientIdField);
		const clientSecret = fetchField(req, this._clientSecretField);

		if (!clientId || !clientSecret) throw new AuthRouteError(AuthRouteError.ERROR_CODES.INVALID_GRANT);

		if (this._passReq) return await this._verify(req, clientId, clientSecret);
		else return await this._verify(clientId, clientSecret);
	}
}
