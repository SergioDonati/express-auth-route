'use strict';

const AuthRouteError = require('./AuthRouteError');

function responseError(req, res, token_type, error){
	if (!(error instanceof AuthRouteError)) error = new AuthRouteError(error);
	if(error.status == 401 && token_type){
		res.set('WWW-Authenticate', token_type);
	}
	res.status(error.status || 400).json(error.toJSONResponse());
}

/**
 * @see https://tools.ietf.org/html/rfc6750
 */
function getBearerToken(req){
	let token = req.method == 'POST' ? req.body.access_token : req.query.access_token;
	// Check Bearer Token in header
	if (!token && req.get('Authorization')){
		const parts = req.get('Authorization').split(' ');
		if (parts.length != 2) throw new AuthRouteError(AuthRouteError.ERROR_CODES.INVALID_TOKEN);
		const scheme = parts[0];
		const credentials = parts[1];
		if (/^Bearer$/i.test(scheme)) token = credentials;
	}
	return token;
}

/**
 *	@see https://tools.ietf.org/html/rfc6749
 */
module.exports = class AuthRoute{

	constructor(options={}){
		this._token_type = options.token_type || 'Bearer'; //default is bearer
		this._getToken = options.getToken || getBearerToken; // default function for get bearer token
		this._authenticators = new Map();
		this._authorizers = new Map();
		this._generateToken = options.generateToken || (async (params) => { throw new Error('YOU MUST implement generateToken method.'); })
		this._checkAccessToken = options.checkAccessToken || (async (req, token, token_type) => { throw new Error('YOU MUST implement checkToken method.'); })
		this._checkRefreshToken = options.checkRefreshToken || (async (req, token, token_type) => { throw new Error('YOU MUST implement checkRefreshToken method.'); })
		this._verifyClient = options.verifyClient || (async (req, params) => { return true; })
	}

	// Developer must implement you logic
	generateToken(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(params) where params is the result of checkAccessToken or checkRefreshToken');
		this._generateToken = fun;
	}

	/**
	 *	Developer must implement your logic
	 * 	The checkAccessToken can throw
	 * 		PredefinedError('invalid_token') if access token was invalid
	 */
	checkAccessToken(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(req, token, token_type)');
		this._checkAccessToken = fun;
	}

	/**
	 *	Developer must implement your logic
	 *	can be optional if refresh token is not used
	 *	The checkRefreshToken can throw
	 *		PredefinedError('invalid_grant') if refresh token was invalid
	 */
	checkRefreshToken(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(req, token, token_type)');
		this._checkRefreshToken = fun;
	}

	/**
	 * Developer must implement your logic
	 * The verifyClient can throw
	 * 		PredefinedError('invalid_client') if access token was invalid
	 * a fail must also set the header WWW-Authenticate with the expected scheme used by client
	 * This function is optional, by default return true, you can define this function
	 * otherwise define your login directly in authenticate method of grant authenticator
	 * the difference is that verifyClient is called also for 'refresh_token' grant type
	 * while authenticate is called only if grant_type is equals to the specified authenitcator grant
	 */
	verifyClient(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(req, {grant_type})');
		this._verifyClient = fun;
	}

	PredefinedError(code, statusCode){
		return AuthRoute.PredefinedError(code, statusCode);
	}

	static PredefinedError(code, statusCode){
		let msg = AuthRouteError.ERROR_DESCRIPTION[code];
		if(!msg) msg = code;
		return new AuthRouteError(msg, code, statusCode);
	}

	/**
	 * The authenticator is an object that has authenticate method
	 *	the authenticate function can throw
	 *		PredefinedError('invalid_grant')
	 *		PredefinedError('invalid_client')
	 *		PredefinedError('invalid_request')
	 *  if authentication fail or something go wrong
	 * the grant_type 'refresh_token' not work cause is handled internally and call checkRefreshToken function
	 */
	addAuthenticator(grant_type, authenticator){
		if (!authenticator || typeof authenticator.authenticate !== 'function') throw new Error('Invalid authenticator, MUST implement authenticate(req) method.');
		this._authenticators.set(grant_type, authenticator);
	}

	/**
	 *	The authorizer function can throw
	 * 		PredefinedError('access_denied') if authorization fail
	 */
	addAuthorizer(name, authorizer){
		if (typeof authorizer !== 'function') throw new Error('Invalid authorizer, MUST be a function(req, ...args)');
		this._authorizers.set(name, authorizer);
	}

	/**
	 *	Middleware for handle the request of access token
	 * @return an express middleware that handle the request of access token
	 */
	authenticate(){
		return (req, res, next)=>{
			(async () =>{
				const grant_type = req.method == 'POST' ? req.body.grant_type : req.query.grant_type;
				if (!grant_type) throw new AuthRouteError(AuthRouteError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);

				await this._verifyClient(req, {grant_type: grant_type});

				let params = null;
				if(grant_type == 'refresh_token'){
					const refresh_token = req.method == 'POST' ? req.body.refresh_token : req.query.refresh_token;
					params = await this._checkRefreshToken(req, refresh_token);
				}else{
					if (!this._authenticators.has(grant_type)) throw new AuthRouteError(AuthRouteError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);
					params = await this._authenticators.get(grant_type).authenticate(req);
				}
				return await this._generateToken(params, {grant_type: grant_type});
			})()
			.then((result) =>{
				if(!result) throw new Error('generateToken function must return an object with \'access_token\' defined');
				if(!result.access_token) console.warn("Your generateToken function must resturn an object with at least the field 'access_token' defined.");

				res.set('Cache-Control', 'no-store');
				res.set('Pragma', 'no-cache');
				// pass the authentication
				res.json({
					access_token: result.access_token,
					token_type: result.token_type || this._token_type, // generateToken() result can override the token_type
					expires_in: result.expires_in,
					refresh_token: result.refresh_token,
					scope: result.scope,
				});
			}).catch(error => {
				responseError(req, res, null, error); // authentication failed
			});
		}
	}

	/**
	 *	Middleware for check if the request was authorized
	 * @return an express middleware that check the autorizations
	 */
	authorize(name, ...args){
		return (req, res, next)=>{
			(async () => {
				const access_token = await this._getToken(req);
				if (!access_token){
					throw this.PredefinedError(AuthRouteError.ERROR_CODES.INVALID_REQUEST, 401);
				}
				await this._checkAccessToken(req, access_token, {token_type: this._token_type});

				if (!name) return; // not other check needs
				if (!this._authorizers.has(name)){
					console.warn('Called authorize method with param name: "%s", but none authorizer with this name was registered.', name);
					return;
				}
				return this._authorizers.get(name)(req, ...args);
			})()
			.then((result)=>{
				if(result == false){
					throw this.PredefinedError(AuthRouteError.ERROR_CODES.ACCESS_DENIED, 401);
				}
				next(); // pass the authorize
			}).catch( error => {
				responseError(req, res, this._token_type, error); // fail the authorize
			});
		}
	}
}
