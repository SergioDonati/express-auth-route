
const request = require('supertest');
const should = require('should');
const express = require('express');
const AuthRoute = require('./..');

describe('FAILURES', function(){
	const app = express();
	const authRoute = new AuthRoute();

	authRoute.addAuthenticator('password', new AuthRoute.PasswordAuthenticator({}, async (username, password)=>{
		if (username == 'admin' && password == '1234') return {username:'admin'};
		else throw AuthRoute.PredefinedError('invalid_grant');
	}));

	app.get('/token', authRoute.authenticate());

	const agent = request.agent(app);

	it('should return invalid_grant error', function(done){
		agent.get('/token').expect(400).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('error', 'unsupported_grant_type');
			done();
		});
	});

	it('should return unsupported_grant_type error', function(done){
		agent.get('/token?grant_type=credentials').expect(400).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('error', 'unsupported_grant_type');
			done();
		});
	});

	it('should return invalid_grant error', function(done){
		agent.get('/token?grant_type=password').expect(400).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('error', 'invalid_grant');
			done();
		});
	});

	it('should return server_error error', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(500).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('error', 'server_error');
			done();
		});
	});
})
