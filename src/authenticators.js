'use string';

function fetchField(req, field){
	if (req.method == 'GET'){
		return req.query[field];
	}else if(req.method == 'POST'){
		return req.body[field];
	}
	return undefined;
}

/**
 *	Implement Resource Owner Password Credentials Grant
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

	authenticate(req, done){
		const username = fetchField(req, this._usernameField);
		const password = fetchField(req, this._passwordField);

		if (!username || !password) return done('invalid_credentials');

		if (this._passReq) this._verify(req, username, password, done);
		else this._verify(username, password, done);
	}
 }
