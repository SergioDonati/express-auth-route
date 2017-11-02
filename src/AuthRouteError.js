'use strict';

const ERROR_CODES = {
	INVALID_REQUEST: 'invalid_request',
	UNAUTHORIZED_CLIENT: 'unauthorized_client',
	ACCESS_DENIED: 'access_denied',
	UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',
	INVALID_GRANT: 'invalid_grant',
	INVALID_CLIENT: 'invalid_client',
	INVALID_SCOPE: 'invalid_scope',
	INVALID_TOKEN: 'invalid_token',
	SERVER_ERROR: 'server_error',
	TEMPORARILY_UNAVABLE: 'temporarily_unavailable',
	INVALID_CREDENTIALS: 'invalid_credentials',
	INSUFFICIENT_SCOPE: 'insufficient_scope'
};

const ERROR_DESCRIPTION = {
	invalid_request: 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
	unauthorized_client: 'The client is not authorized to request an authorization code using this method.',
	access_denied: 'The resource owner or authorization server denied the request.',
	unsupported_grant_type: 'The authorization grant type is not supported by the authorization server.',
	invalid_grant: 'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
	invalid_scope: 'The requested scope is invalid, unknown, or malformed.',
	invalid_client: 'Client authentication failed.',
	invalid_credentials: 'Credentials are wrong or missing.',
	invalid_token: 'Token invalid or expired.',
	server_error: 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
	temporarily_unavailable: 'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
	insufficient_scope: 'The request requires higher privileges than provided by the access token.'
}

module.exports = class AuthRouteError extends Error{
	constructor(msg, errorCode, statusCode){
		if (msg instanceof Error){
			super(msg.message);
			this.originalError = msg;
		}else super(msg);
		this.error_description = this.message;
		if (ERROR_DESCRIPTION[this.message]){
			errorCode = this.message;
			this.error_description[errorCode];
		}
		if (!ERROR_DESCRIPTION[errorCode]) errorCode = ERROR_CODES.SERVER_ERROR;
		if (errorCode == ERROR_CODES.SERVER_ERROR) this.status = 500;
		else if (errorCode == ERROR_CODES.INVALID_CLIENT || errorCode == ERROR_CODES.INVALID_TOKEN) this.status = 401;
		else if (errorCode == ERROR_CODES.INVALID_REQUEST) this.status = 400;
		else if (errorCode == ERROR_CODES.INSUFFICIENT_SCOPE) this.status = 403;
		if(statusCode) this.status = statusCode; // overwrite all previous settings
		this.error_code = errorCode;
	}

	static get ERROR_CODES(){ return ERROR_CODES; }
	static get ERROR_DESCRIPTION(){ return ERROR_DESCRIPTION; }

	toJSONResponse(){
		return {
			error: this.error_code,
			error_description: this.error_description,
			error_uri: null,
			error_extra_message: this.message
		};
	}
}
