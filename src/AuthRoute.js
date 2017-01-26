'use strict';

const AuthRouteError = require('./AuthRouteError');

/**
 *	@see https://tools.ietf.org/html/rfc6749
 */
module.exports = class AuthRoute{

	constructor(){
		this._authenticators = new Map();
		this._authorizers = new Map();
		this._generateToken = (params, callback) => { throw new Error('YOU MUST implement generateToken method.'); };
		this._checkToken = (req, token, callback) => { throw new Error('YOU MUST implement checkToken method.'); }
	}

	// Developer must implement you logic
	generateToken(fun){ this._generateToken = fun;}

	// Developer must implemente your logic
	checkToken(fun){ this._checkToken = fun;}

	_success(token, { token_type = 'bearer', expires_in = null, scope = null } = {}){
		return {
			access_token: token,
			token_type: token_type,
			expires_in: expires_in,	// infinite
			scope: scope
		};
	}

	_fail(res, error){
		if (!(error instanceof AuthRouteError)) error = new AuthRouteError(error);
		res.status(error.status || 400).json(error.toJSONResponse());
	}

	addAuthenticator(grant_type, authenticator){
		if (!authenticator || typeof authenticator.authenticate !== 'function') throw new Error('Invalid authenticator, MUST implement authenticate method.');
		this._authenticators.set(grant_type, authenticator);
	}

	addAuthorizer(name, authorizer){
		if (typeof authorizer !== 'function') throw new Error('Invalid authorizer, MUST be a function.');
		this._authorizers.set(name, authorizer);
	}

	// Array of middlewares for hanlde the request of token
	authenticate(){
		const self = this;
		return [
			(req, res, next)=>{
				const grant_type = req.method == 'POST' ? req.body.grant_type : req.query.grant_type;
				if (!grant_type) return next(AuthRouteError.ERROR_CODES.INVALID_GRANT);
				if (!self._authenticators.has(grant_type)) return next(AuthRouteError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);
				self._authenticators.get(grant_type).authenticate(req, (err, params)=>{
					if (err) return next(err);
					self._generateToken(params, function(err, token, options){
						if (err) return next(err);
						res.json(self._success(token, options));
					});
				});
			},
			(err, req, res, next)=>{ self._fail(res, err);}
		]
	}

	/**
	 *	Middleware for check if the request was authorized
	 */
	authorize(name, ...args){
		const self = this;
		return [
			(req, res, next)=>{
				let access_token = req.method == 'POST' ? req.body.access_token : req.query.access_token;
				// Check Bearer Token in header
				if (!access_token && req.get('Authorization')){
					const parts = req.get('Authorization').split(' ');
					if (parts.length != 2) return next(AuthRouteError.ERROR_CODES.INVALID_TOKEN);
					const scheme = parts[0];
					const credentials = parts[1];
					if (/^Bearer$/i.test(scheme)) access_token = credentials;
				}
				if (!access_token) return next(AuthRouteError.ERROR_CODES.ACCESS_DENIED);
				self._checkToken(req, access_token, next);
			},
			(req, res, next) => {
				if (!name) return next();
				if (!self._authorizers.has(name)){
					console.warn('Called authorize method with param name: "%s", but none authorizer with this name was registered.', name);
					return next();
				}
				self._authorizers.get(name)(req, ...args, next);
			},
			(err, req, res, next)=>{ self._fail(res, err);}
		]
	}
}
