
const request = require('supertest');
const should = require('should');
const express = require('express');
const AuthRoute = require('./..');

describe('ACCESS', function(){
	const app = express();
	const authRoute = new AuthRoute();

	authRoute.generateToken(async (params, {grant_type}) =>{
		const expires_date = new Date();
		expires_date.setDate(expires_date.getDate() + 3); // 3 day
		if(grant_type=='password' || grant_type == 'refresh_token'){
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
		if (/refreshtoken\:(.)+/.test(token)) return {username:'refreshed_admin'}; //success
		else throw AuthRoute.PredefinedError('invalid_grant');
	});

	authRoute.addAuthenticator('password', new AuthRoute.PasswordAuthenticator({}, async(username, password)=>{
		if (username == 'admin' && password == '1234') return {username:'admin'};
		else throw AuthRoute.PredefinedError('invalid_grant');
	}));

	app.get('/token', authRoute.authenticate());
	app.get('/secure', authRoute.authorize(), function(req, res, next){
		res.json({success:true});
	});

	const agent = request.agent(app);

	it('should return access_token', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			done();
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

	it('should access authorized', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/secure?access_token='+res.body.access_token).expect(200).end(done);
		});
	});

	it('should access authorized with Authorization Bearer header', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/secure').set('Authorization', 'Bearer '+res.body.access_token).expect(200).end(done);
		});
	});

	it('should refresh the token', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);

			should(res.body).have.property('access_token');
			should(res.body).have.property('refresh_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/token?grant_type=refresh_token&refresh_token='+res.body.refresh_token)
			.expect(200).end(function(err, res){
				if (err) return done(err);

				should(res.body).have.property('access_token');
				should(res.body).have.property('token_type', 'Bearer');
				done();
			});
		});
	});
})
