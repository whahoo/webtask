var app = new (require('express'))();
var bodyParser = require('body-parser');
var request = require('request-promise');
var wt = require('webtask-tools');
var aws = require('aws-sdk');

var jwt = require('jsonwebtoken');
var ejwt = require('express-jwt');
var jwks = require('jwks-rsa');

var jwtCheck = ejwt({
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

var jwtIDCheck = ejwt({
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

function getToken() {
  var options = {
    method: 'POST',
    url: 'https://iag-api.au.auth0.com/oauth/token',
    headers: { 'content-type': 'application/json' },
    body: {"client_id":context.secrets.AUTH0_CLIENT_ID,
          "client_secret": context.secrets.AUTH0.CLIENT_SECRET,
          "audience":"https://iag-api.au.auth0.com/api/v2/",
          "grant_type":"client_credentials"},
    json: true
  };
  const client = jwks.jwksClient({
      strictSsl: true,
      jwksUri: 'https://iag-api.au.auth0.com/.well-known/jwks.json'
  });

  ctx.storage.get(function (error, data) {
    if (error) return error;
    data = data || {};
    if (data.auth0_mgmt_token != null ) {
      var storedToken = jwt.decode(data.auth0_mgmt_token);
      client.getSigningKey(storedToken.kid, (err, key) => {
        const signingKey = key.publicKey || key.rsaPublicKey;
        jwt.verify(data.auth0_mgmt_token, signingKey, function(err, decoded) {
          if (!err) return data.auth0_mgmt_token;
          return request(options)
          .then(function(body) {
            return body.access_token;
          })
          .then( function(token) {
            ctx.storage.get(function (error, data) {
              if (error) return error;
              data = data || {};
              data.auth0_mgmt_token = token;
              ctx.storage.set(data, function (error) {
                if (error) return error;
              });
            });
            return token;
          });
        });
      });
    }
  });
      
    

}
function getAPIs(token) {
  return request(
          {
            url: 'https://iag-api.au.auth0.com/api/v2/resource-servers',
            headers: { "Authorization": "Bearer " + token },
            json: true
          }
        );
  
}
app.get('/listApis', jwtCheck, function (req, res, next) {

    getToken()
    .then(getAPIs(token))
    .catch()
    .then(function(resp) {
      res.json( resp.map(function(api) {
        return {"id": api.id,
        "name": api.name,
        "identifier": api.identifier};
      }));
    })
    .catch(next);
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














