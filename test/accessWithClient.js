
const request = require('supertest');
const should = require('should');
const express = require('express');
const AuthRoute = require('./..');

describe('ACCESS WITH CLIENT', function(){
	const app = express();
	const authRoute = new AuthRoute();

	authRoute.generateToken(async (params, {grant_type}) =>{
		const expires_date = new Date();
		expires_date.setDate(expires_date.getDate() + 3); // 3 day
		if(grant_type=='password'){
			return {
				access_token: 'token:'+params.username,
				expires_in: (expires_date.getTime() - (new Date()).getTime()) / 1000,
				refresh_token: 'refreshtoken:'+params.username
			};
		}else if(grant_type=='client_credentials'){
			return {
				access_token: 'apptoken:'+params.clientId,
				token_type: 'Basic',
				expires_in: (expires_date.getTime() - (new Date()).getTime()) / 1000
			};
		}
	});

	authRoute.checkAccessToken(async (req, token, params)=>{
		if (/token\:(.)+/.test(token)) return; //success
		else throw AuthRoute.PredefinedError('access_denied');
	});

	authRoute.checkRefreshToken(async (req, token)=>{
		if (/refreshtoken\:(.)+/.test(token)) return; //success
		else throw AuthRoute.PredefinedError('invalid_grant');
	});

	authRoute.addAuthenticator('password', new AuthRoute.PasswordAuthenticator({}, async(username, password)=>{
		if (username == 'admin' && password == '1234') return {username:'admin'};
		else throw AuthRoute.PredefinedError('invalid_grant');
	}));

	authRoute.addAuthenticator('client_credentials', new AuthRoute.ClientCredentialsAuthenticator({}, async(clientId, clientSecret)=>{
		if (clientId == 'myapp' && clientSecret == '1234') return {clientId:'myapp'};
		else throw AuthRoute.PredefinedError('invalid_client');
	}));

	authRoute.verifyClient(async (req, {grant_type})=>{
		if(grant_type !== 'password' && grant_type !== 'refresh_token') return true;
		if(!req.get('Authorization')) throw AuthRoute.PredefinedError('invalid_client');

		const parts = req.get('Authorization').split(' ');
		if (parts.length != 2) throw AuthRoute.PredefinedError('invalid_client');
		const scheme = parts[0];
		const credentials = parts[1];
		if (/^Basic$/i.test(scheme)) token = credentials;
		if (/apptoken\:(.)+/.test(token)) return {clientId:'myapp'};
		else throw AuthRoute.PredefinedError('invalid_client');
	});

	app.get('/token', authRoute.authenticate());
	app.get('/secure', authRoute.authorize(), function(req, res, next){
		res.json({success:true});
	});

	const agent = request.agent(app);

	it('should return access_tokens and authorize access', function(done){
		agent.get('/token?grant_type=client_credentials&client_id=myapp&client_secret=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Basic');

			agent.get('/token?grant_type=password&username=admin&password=1234')
			.set('Authorization', 'Basic '+res.body.access_token)
			.expect(200).end(function(err, res){
				if (err) return done(err);
				should(res.body).have.property('access_token');
				should(res.body).have.property('token_type', 'Bearer');
				agent.get('/secure')
				.set('Authorization', 'Bearer '+res.body.access_token).expect(200).end(done);
			});
		});

	});

	it('should access not authorized', function(done){
		agent.get('/secure').expect(401).end(function(err, res){
			if (err) return done(err);
			should(res.header).have.property('www-authenticate', 'Bearer');
			should(res.body).have.property('error', 'invalid_request');
			done();
		});
	});
})
