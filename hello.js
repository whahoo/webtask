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

function getClientNameAndSecret(token, client_id) {
  return request.get("https://iag-api.au.auth0.com/api/v2/clients/" + client_id,
  {
    headers: { "Authorization": "Bearer " + token },
    qs: { fields : "name,client_id,client_secret,description" },
    json: true
  });
}

app.get('/getCredentials', jwtCheck, function (req, res, next) {
   getToken(req.webtaskContext)
  .then(function(token) {
    return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ req.user.sub, {
        headers: { "Authorization": "Bearer " + token },
        json: true
    })
    .then(function(user) {
     // console.log(user);
      return Promise.all( user.app_metadata.clients.map( (client) => { return getClientNameAndSecret(token, client.id) } ) );
    })
    .then(function (resp) {
      //console.log(resp);
      res.json( resp );
    });
  })
  .catch(next);
});


app.post('/addApplication', jwtCheck, function (req, res, next) {
  getToken(req.webtaskContext)
  .then(function(token) {
    return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ req.user.sub, {
        headers: { "Authorization": "Bearer " + token },
        json: true
    })
    .then(function(user) {
      //console.log(req.body);
      return request.post("https://iag-api.au.auth0.com/api/v2/clients",
      {
        headers: { "Authorization": "Bearer " + token },
        json: true,
        body: {
          name: req.body.appName,
          description: user.email + " " + req.body.appName,
          token_endpoint_auth_method: "client_secret_post",
          app_type: "non_interactive",
          client_metadata: {
            owner: user.user_id,
            email: user.email
          }
        }
      })
      .then(function (resp) {
        //console.log(user);
        var clients = user.app_metadata.clients || [];
        clients.push( { id: resp.client_id, name: resp.name } );
      
        return request({
          method: "PATCH",
          uri: "https://iag-api.au.auth0.com/api/v2/users/"+ user.user_id,
          headers: { "Authorization": "Bearer " + token },
          body: {
            app_metadata: { "clients": clients }
          },
          json: true
        });
      });
    })
    .then(function(resp){
      //console.log(resp);
      res.json({"result": "Client Created"});
    });
  })
  .catch(next);
});

app.post("requestGrant", jwtCheck, function(req, res, next) {
   getToken(req.webtaskContext)
  .then(function(token) {
    return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ req.user.sub, {
        headers: { "Authorization": "Bearer " + token },
        json: true
    })
    .then(function(user) {
      var grantsRequests = user.app_metadata.grantsRequests || [];
      var grants = user.app_metadata.grants || [];
      
      if (grantsRequests.findIndex( grantReq => { 
        grantReq.client_id === req.body.client_id &&
        grantsReq.api_id === req.body.api_id
      })) {
        
      }
      grantsRequests.push( {
        client_id: req.body.client_id,
        api_id: req.body.api_id,
        scopes: req.body.scopes,
        id: uuid()
      });
      return request({
        method: "PATCH",
        uri: "https://iag-api.au.auth0.com/api/v2/users/"+ user.user_id,
        headers: { "Authorization": "Bearer " + token },
        body: {
          app_metadata: { "grantsRequests": grantsRequests }
        },
        json: true
      });
    });
  })
  .then(function(resp){
    //console.log(resp);
    res.json({"result": "Client Created"});
  })
  .catch(next);
});

app.post("approveGrantRequest", jwtCheck, function(req,res,next) {
  getToken(req.webtaskContext)
  .then(function(token) {
    return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ req.user.sub, {
        headers: { "Authorization": "Bearer " + token },
        json: true
    })
    .then(function(ApprovingUser) {
        return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ req.body.user_id, {
          headers: { "Authorization": "Bearer " + token },
          json: true
        })
        .then(function(RequestingUser) {
          return request.get("https://iag-api.au.auth0.com/api/v2/resource-servers/"+ req.body.api_id, {
            headers: { "Authorization": "Bearer " + token },
            json: true
          })
          .then(function(Api) {
            var grantReq = RequestingUser.app_metadata.grantsRequests.find( (grantReq) => grantReq.client_id == req.body.client_id);
            if (grantReq && grantReq.api_id == req.body.api_id) {
              var apiOwner = ApprovingUser.app_metadata.apis.find( (api) => api.id == grantReq.api_id);
              var scopesAllowed = req.body.scopes.every( (reqScope) => {
                Api.scopes.some( scope => { scope.value === reqScope} );
              });
              if ( scopesAllowed ) {
                return request.post("https://iag-api.au.auth0.com/api/v2/client-grants/", {
                  headers: { "Authorization": "Bearer " + token },
                  body: {
                    "client_id": grantReq.client_id,
                    "audience": "https://api.iag.com.au/",
                    "scope": req.body.scopes
                  },
                  json: true
                  })
                  .then()
                .then(function(resp) {
                  var grantsRequests = user.app_metadata.grantsRequests || [];
                  var grants = user.app_metadata.grants || [];
                  
                  grantReq.approved = Date.now();
                  grantReq.grant_id = resp.id;
                  grants.push(grantReq);
                  grantsRequests.splice(grantsRequests.findIndex( gr => grantReq.id === gr.id));
                  return request({
                    method: "PATCH",
                    uri: "https://iag-api.au.auth0.com/api/v2/users/"+ req.user.sub,
                    body: {
                      app_metadata: {
                        "grantsRequests": grantsRequests,
                        "grants": grants
                        
                      }
                    }
                  });
                });
              }
            }
          });
        });
    });
  })
  .catch(next);
});


app.get("/getGrants/:client_id", jwtCheck, function(req, res, next) {
    getToken(req.webtaskContext)
  .then(function(token) {
    return request.get("https://iag-api.au.auth0.com/api/v2/client-grants",
    { headers: { "Authorization": "Bearer " + token },
      qs : { audience: "https://api.iag.com.au/" },
      json: true }
    );
  }).
  then(function(resp) {
      res.json ( resp.filter( (grant) => { return grant.client_id == req.params.client_id}) );
  })
  .catch(next);
});

app.post('/addApi', jwtCheck, function(req, res, next) {
  getToken(req.webtaskContext)
  .then(function(token) {
    return request.post("https://iag-api.au.auth0.com/api/v2/resource-servers",
      {
        headers: { "Authorization": "Bearer " + token },
        json: true,
        body: {
          "name": req.body.name,
          "identifier": req.body.endpoint,
          "signing_alg": "RS256",
          "token_lifetime": req.body.token_lifetime,
          "scopes" : req.body.scopes.map( (scope) => { return {"value": scope} })
        }
      })
      .then(function(resp) {
        return request.get("https://iag-api.au.auth0.com/api/v2/resource-servers/591a46ade6d8800cc84fdf05",
          {
            headers: { "Authorization": "Bearer " + token },
            json: true
          })
          .then(function(resp) {
            var allscopes = resp.scopes.concat(req.body.scopes.map( (scope) => { return {"value": scope} }));
            return request({
              method:"PATCH",
              uri: "https://iag-api.au.auth0.com/api/v2/resource-servers/591a46ade6d8800cc84fdf05",
              headers: { "Authorization": "Bearer " + token },
              body: { "scopes": allscopes },
              json: true
            });
        });
      });
    })
    .then(function(resp) {
      res.json(resp);
    })
    .catch(next);
});

app.get('/listApis', jwtCheck, function (req, res, next) {

    getToken(req.webtaskContext)
    .then(function(token) {
      return getAPIs(token);
      })
    .then(function(resp) {
      res.json( resp.map(function(api) {
        return {
          "id": api.id,
          "name": api.name,
          "identifier": api.identifier,
          "scopes" : api.scopes
        };
      }));
    })
    .catch(next);
});

app.get('/user', jwtCheck, function( req,res,next) {
  request.get('https://iag-api.au.auth0.com/userinfo',
    {
      headers: { "Authorization": req.headers.authorization },
      json: true
    }
  )
  .then( function(resp) {
    res.json(resp);
  })
  .catch(next);
});

app.get('/clearToken', function (req,res) {
  req.webtaskContext.storage.set( {} ,{ force: 1 },  function (error) {
          if (error) return error;
          res.send("data cleared");
        });
});

function getTokenFromStorage(context) {
  const jwksClient = jwks({
      strictSsl: true,
      jwksUri: 'https://iag-api.au.auth0.com/.well-known/jwks.json'
  });
  
  return new Promise( (resolve, reject) => {
    context.storage.get(function (error, data) {  // Look for Token in storage
      if (error) { reject(error); return; }
      data = data || {};
     // console.log("storage", data.auth0_mgmt_token);
      if (data.auth0_mgmt_token == null ) { reject("No Token in storage"); return; }
      var storedToken = jwt.decode(data.auth0_mgmt_token, {complete: true});
      jwksClient.getSigningKey(storedToken.header.kid, (err, key) => {  // Get the publicKey of the stored token
        if(err) { reject(err); return }
        const signingKey = key.publicKey || key.rsaPublicKey;
       // console.log("storedToken key", signingKey);
        jwt.verify(data.auth0_mgmt_token, signingKey, function(err, decoded) { //verify the token
          if (!err) { resolve(data.auth0_mgmt_token); return; }
            reject(err);
            console.log("storedToken not valid", err);
          });
        });
    });
  });
}

function getTokenNew(context) {
  var options = {
    method: 'POST',
    url: 'https://iag-api.au.auth0.com/oauth/token',
    headers: { 'content-type': 'application/json' },
    body: {"client_id":context.secrets.AUTH0_CLIENT_ID,
          "client_secret": context.secrets.AUTH0_CLIENT_SECRET,
          "audience":"https://iag-api.au.auth0.com/api/v2/",
          "grant_type":"client_credentials"},
    json: true
  };

  return request(options)
    .then(function(body) {
     // console.log( "access_token", body.access_token);
      return body.access_token;
    })
    .then( function(token) {
     // console.log("token", token);
      context.storage.get(function (error, data) {
        if (error) return error;
        data = data || {};
        data.auth0_mgmt_token = token;
        context.storage.set(data, function (error) {
          if (error) return error;
        });
      });
      return token;
    });
}

function getToken(context) {
  return getTokenFromStorage(context)
        .catch(function(err) {
          console.log("no valid token in storage", err);
          return getTokenNew(context);
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

app.use(function(err, req, res, next) {
  console.log("ERROR", err);
  res.json( err.error);
});

function uuid() {
  'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
    return v.toString(16);
});
}

module.exports = wt.fromExpress(app);














