# Express Authorize Route

Helper for authorize access to [Express](http://expressjs.com/) routers with token.

## Install

This module require node >= 6.5.0 because is written with the last ECMAScript 6 features, so firstly check your version.

```bash
$ npm install express-auth-route --save
```

## Example

```javascript
const AuthRoute = require('express-auth-route');
const auth = new AuthRoute();

auth.generateToken(function(param1, callback){
	... your logic here
	callback(null, token);
});

auth.checkToken(function(req, token, callback){
	... your logic here
	// if you need in your next middlewares or endpoints
	req.access_token = token;
	// if you have fetched user by the token you can pass in the next
	req.user = user;
	callback();
});

// Add at least one authenticator
// when request come grant_type must be equals to your authenticator
// you can create your custom authenticator, the only required implemented method is 'authenticate(req, done)'
auth.addAuthenticator('password', new AuthRoute.PasswordAuthenticator(function(username, password, done){
	... your logic here
	callback(null, param1);
}));

// Authorizers are optional
auth.addAuthorizer('admin', function(req, ...parameters, next){
	... your logic here
	if (isAdmin(req.user)) next();
	else next(new Error('Access Denied!'));	// Error will be handled by AuthRoute
});

router.get('/token', auth.authenticate());

router.get('/secure', auth.authorize(), function(req, res){
	res.render('secure-page');
});
router.get('/secure/admin', auth.authorize('admin', ...parameters), function(req, res){
	res.render('secure-page');
});
```

## How work

TODO

## Credits

- [Sergio Donati](https://github.com/SergioDonati)

## License

[MIT](LICENSE)

Copyright (c) 2016 Sergio Donati
