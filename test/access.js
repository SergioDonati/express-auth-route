
const request = require('supertest');
const should = require('should');
const express = require('express');
const AuthRoute = require('./..');

describe('ACCESS', function(){
	const app = express();
	const authRoute = new AuthRoute();

	authRoute.generateToken(function(params, done){
		done(null, 'token:'+params.username);
	});

	authRoute.checkToken(function(req, token, done){
		if (/token\:(.)+/.test(token)) return done();
		else done('access_denied');
	});

	authRoute.addAuthenticator('password', new AuthRoute.PasswordAuthenticator({}, function(username, password, done){
		if (username == 'admin' && password == '1234') return done(null, {username:'admin'});
		else done('invalid_credentials');
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
			should(res.body).have.property('token_type', 'bearer');
			done();
		});
	});

	it('should access not authorized', function(done){
		agent.get('/secure').expect(400).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('error', 'access_denied');
			done();
		});
	});

	it('should access authorized', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'bearer');
			agent.get('/secure?access_token='+res.body.access_token).expect(200).end(done);
		});
	});
	it('should access authorized with Authorization Bearer header', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'bearer');
			agent.get('/secure').set('Authorization', 'Bearer '+res.body.access_token).expect(200).end(done);
		});
	});
})
