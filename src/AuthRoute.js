'use strict';

const AuthRouteError = require('./AuthRouteError');

/**
 *	@see https://tools.ietf.org/html/rfc6749
 */
modules.exports = class AuthRoute{

	constructor(){
		this._authenticators = new Map();
		this._authorizers = new Map();
		this._generateToken = (params, callback) => { throw new Error('YOU MUSt implement generateToken of OAuth2.'); };
		this._checkToken = (token, callback) => { throw new Error('YOU MUSt implement checkToken of OAuth2.'); }
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

	_fail(error){
		if (!error instanceof AuthRouteError) error = new AuthRouteError(error);
		return error.toJSONResponse();
	}

	addAuthenticator(grant_type, authenticator){
		if (!authenticator || typeof authenticator.authenticate !== 'function') throw new Error('Invalid authenticator, MUST implement authenticate function.');
		this._authenticators.set(grant_type, authenticator);
	}

	addAuthorizer(name, authorizer){
		if (typeof authorizer !== 'function') throw new Error('Invalid authorizer, MUST be a function.');
		this._authorizers.set(name, authorizer);
	}

	// Array of middlewares for hanlde the request of token
	authenticate(){
		return [
			(req, res, next)=>{
				const grant_type = req.method == 'POST' ? req.body.grant_type : req.query.grant_type;
				if (!grant_type) return next(AuthRouteError.ERROR_CODES.INVALID_GRANT);
				if (this._authenticators.has(grant_type)) return next(AuthRouteError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);
				this._authenticators.get(grant_type).authenticate(req, (err, params)=>{
					if (err) return next(err);
					this._generateToken(params, function(err, token, options){
						if (err) return next(err);
						res.json(this._success(token, options));
					});
				});
			},
			(err, req, res, next)=>{ res.json(this._fail(err));}
		]
	}

	/**
	 *	Middleware for check if the request was authorized
	 */
	authorize(name, ...args){
		return [
			(req, res, next)=>{
				let access_token = req.method == 'POST' ? req.body.access_token : req.query.access_token;
				if (!access_token){
					const parts = authorization.split(' ');
					if (parts.length != 2) return false;
					const scheme = parts[0];
					const credentials = parts[1];
					if (/^Bearer$/i.test(scheme)) access_token = credentials;
					else return next(AuthRouteError.ERROR_CODES.ACCESS_DENIED);
				}
				this._checkToken(req, access_token, next);
			},
			(req, res, next) => {
				if (!name) return next();
				if (this._authorizers.has(name)){
					console.warn('Called authorize method with param name: "%s", but none authorizer with this name was registered.', name);
					return next();
				}
				this._authorizers.get(name)(req, ...args, next);
			},
			(err, req, res, next)=>{ res.json(this._fail(err));}
		]
	}
}
