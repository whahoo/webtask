var app = new (require('express'))();
var bodyParser = require('body-parser');
var request = require('request-promise');
var wt = require('webtask-tools');

var jwt = require('express-jwt');
var jwks = require('jwks-rsa');

var jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: "https://iag-api.au.auth0.com/.well-known/jwks.json"
    }),
    audience: 'https://api.auth.auiag.corp/kongAPI',
    issuer: "https://iag-api.au.auth0.com/",
    algorithms: ['RS256']
});

var jwtIDCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: "https://iag-api.au.auth0.com/.well-known/jwks.json"
    }),
    issuer: "https://iag-api.au.auth0.com/",
    algorithms: ['RS256']
});

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

app.get('/getCredentials', jwtCheck, function (req, res, next) {
  request.get("https://iag-api.au.auth0.com/userinfo",
  {headers: {
    "Authorization": req.headers.authorization
  },
    json: true
  })
  .then(function(body) {
    return request.get("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/consumers/"+body.email + "/oauth2",
  {
    json: true
  })
  .then(function (resp) {
    res.json( resp);
  });
  })
  .catch(next);
});

app.post('/addApplication', jwtCheck, function (req, res, next) {
   console.log(req);
  request.get("https://iag-api.au.auth0.com/userinfo",
  {headers: {
    "Authorization": req.headers.authorization
  },
    json: true
  })
  .then(function(body) {
     console.log(req.body);
    return request.post("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/consumers/"+body.email + "/oauth2",
      {
        form: {
          name: req.body.appName,
          redirect_uri: "http://127.0.0.1/"
        }
      })
      .then(function (resp) {
        res.json( resp);
      });
  })
  .catch(next);
});


app.post('/getConsumer', jwtCheck, function (req, res, next) {
  request.post("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/consumers/"+req.user.email,
  {
    form: {
      username: req.user.email,
      custom_id: req.user.sub
    }
  })
  .then(function (resp) {
    res.json( resp);   
  })
  .catch(next);
});

app.post('/addConsumer', jwtCheck, function (req, res, next) {
  request.get("https://iag-api.au.auth0.com/userinfo",
  {headers: {
    "Authorization": req.headers.authorization
  },
    json: true
  })
  .then(function(body) {
    return request.post("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/consumers",
      {
        form: {
          username: body.email,
          custom_id: body.sub
        }
      })
      .then(function (resp) {
        res.json( resp);
      });
  })
  .catch(next);
});


app.get('/listApis', jwtCheck, function (req, res, next) {

    request.get("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/apis", {
      json: true
    }).
    then(function (resp) {
      console.log( req );
      res.json( resp);
    }).
    catch(next);
});

app.get('/listConsumers', jwtCheck, function (req, res, next) {

    request.get("http://kong-elb-kongload-1frr8tyzpo0je-2126382179.ap-southeast-2.elb.amazonaws.com:8001/consumers", {
      json: true
    }).
    then(function (resp) {
      console.log( req );
      res.json( resp);
    }).
    catch(next);
});

app.get('/user', jwtIDCheck, function (req, res, next) {
     res.json( req.user );
});

app.use(function(err, req, res, next) {
  console.log("ERROR", err);
  res.json( err.error);
});



module.exports = wt.fromExpress(app);














