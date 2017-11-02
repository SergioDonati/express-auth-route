# Express Authorize Route

![Travis](https://img.shields.io/travis/SergioDonati/express-auth-route.svg?style=flat-square)
![bitHound](https://img.shields.io/bithound/dependencies/github/SergioDonati/express-auth-route.svg?style=flat-square)
![bitHound](https://img.shields.io/bithound/devDependencies/github/SergioDonati/express-auth-route.svg?style=flat-square)


[![npm](https://img.shields.io/npm/v/express-auth-route.svg?style=flat-square)](https://www.npmjs.com/package/express-auth-route)
[![npm](https://img.shields.io/npm/l/express-auth-route.svg?style=flat-square)](https://www.npmjs.com/package/express-auth-route)


Helper for authorize access to [Express](http://expressjs.com/) routers with token.

## Install

```bash
$ npm install express-auth-route --save
```

## Example

```javascript
const AuthRoute = require('express-auth-route');
const auth = new AuthRoute();

auth.generateToken(async(params)=>{
	... your logic here
	return token;
});

auth.checkAccessToken(async (req, token, params)=>{
	... your logic here
	// if you need in your next middlewares or endpoints
	req.access_token = token;
	// if you have fetched user by the token you can pass in the next
	req.user = user;

	return; // pass the check

	// or throw AuthRoute.PredefinedError('access_denied');
});

// Add at least one authenticator
// when request come grant_type must be equals to your authenticator
// you can create your custom authenticator, the only required implemented method is 'authenticate(req, done)'
auth.addAuthenticator('password', new AuthRoute.PasswordAuthenticator(async (username, password)=>{
	... your logic here
	if (username == 'admin' && password == '1234') return {username:'admin'};
	else throw AuthRoute.PredefinedError('invalid_grant');
}));

// Authorizers are optional
auth.addAuthorizer('admin', async (req, ...parameters)=>{
	... your logic here
	if (isAdmin(req.user)) next();
	else throw AuthRoute.PredefinedError('Access Denied!');	// Error will be handled by AuthRoute
});


// now defined the express routes

// GET /token return the access_token if authenticate success
router.get('/token', auth.authenticate());

// GET /secure render the secure-page only if we are authorized
router.get('/secure', auth.authorize(), function(req, res){
	res.render('secure-page');
});
// GET /secure/admin render the secure-page only if we are authorized and we pass the admin authorizer
router.get('/secure/admin', auth.authorize('admin', ...parameters), function(req, res){
	res.render('secure-page');
});
```

## How work

Coming soon.

## Credits

- [Sergio Donati](https://github.com/SergioDonati)

## License

[MIT](LICENSE)

Copyright (c) 2016 Sergio Donati
