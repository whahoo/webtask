/*jshint esversion: 6 */

var app = new (require('express'))();
var bodyParser = require('body-parser');
var request = require('request-promise');
var wt = require('webtask-tools');

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

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

app.get('/getCredentials', jwtCheck, function (req, res, next) {
   getToken(req.webtaskContext)
  .then( token => {
    return getUser( token, req.user.sub)
    .then( user => {
      var clients = user.app_metadata.clients || [];
      return Promise.all( clients.map( (client) => { return getClientNameAndSecret(token, client.id); } ) );
    })
    .then( resp => {
      res.json( resp );
    });
  })
  .catch(next);
});

app.post('/addApplication', jwtCheck, function (req, res, next) {
  getToken(req.webtaskContext)
  .then(function(token) {
    return getUser( token, req.user.sub)
    .then(function(user) {
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
            owner_id: user.user_id,
            owner_email: user.email
          }
        }
      })
      .then(function (resp) {
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
      res.json({"result": "Client Created"});
    });
  })
  .catch(next);
});

app.get("/pendingApprovals", jwtCheck, function(req,res,next) {
  getToken(req.webtaskContext)
  .then( token => {
    return getUser(token, req.user.sub)
    .then( user => {
      var apis = user.app_metadata.apis || [];
      if ( apis.length === 0 ) return [];
      var queryArray = apis.map( api => 'app_metadata.grantsRequests.api_id:"'+api.id+'"');
      var api_queryString = queryArray.join(' OR ');

      return request.get("https://iag-api.au.auth0.com/api/v2/users", {
         headers: { "Authorization": "Bearer " + token },
         qs: {
            fields: "user_id,app_metadata.grantsRequests",
            include_fields: true,
            q: "_exists_:app_metadata.grantsRequests AND (" + api_queryString + ")",
            search_engine: "v2"
          },
          json: true
          
      })
      .then( resp => {
        var usersGrants = resp.map( user => {
          var grantRequests = user.app_metadata.grantsRequests.filter( gr => apis.find( a => a.id == gr.api_id ) );
          return grantRequests.map( gr => { gr.user_id = user.user_id; return gr; });
        });
        return [].concat.apply([],usersGrants);
      });
    });
  })
  .then( resp => {
    res.json( resp );
  })
  .catch(next);
});

app.post("/requestGrant", jwtCheck, function(req, res, next) {
   getToken(req.webtaskContext)
  .then(function(token) {
    return getUser(token, req.user.sub)
    .then( user => {
      var grantsRequests = user.app_metadata.grantsRequests || [];
      var grants = user.app_metadata.grants || [];
      //does this client grant exist?
      var index = grants.findIndex( grant => {
          return grant.client_id === req.body.client_id && 
          grant.api_id === req.body.api_id;
        });
     //   console.log ("G", grants, "GR", grantsRequests, "idx", index );
      var newGrant = {};
      
      if (index >= 0) { // use existing grant as the request object and update the scopes
        newGrant = grants[index];
        newGrant.scopes = req.body.scopes;
      }
      else { // create a new grant
         newGrant = {
          client_id: req.body.client_id,
          api_id: req.body.api_id,
          scopes: req.body.scopes,
          id: uuid()
        };
      }
      grantsRequests.push(newGrant);
      
      return updateUserMetaDataGrantRequests( token, user.user_id, grantsRequests );
    });
  })
  .then( resp => {
    res.json({"result": "Client Created"});
  })
  .catch(next);
});

app.post("/approveGrantRequest", jwtCheck, function(req,res,next) {
  getToken(req.webtaskContext)
  .then(function(token) {
      console.log (req.body);
    return Promise.all([ getUser(token, req.user.sub), getUser(token, req.body.user_id), getAPI(token, req.body.api_id) ])
      .then( responses => {
        
        var ApprovingUser = responses[0];
        var RequestingUser = responses[1];
        var Api = responses[2];
        console.log ( "ApprovingUser", ApprovingUser,"RequestingUser", RequestingUser,"API", Api);
    // Does the requesting user have and active grantRequest that matches this approval request
        var grantsRequests = RequestingUser.app_metadata.grantsRequests || [];
        var grants = RequestingUser.app_metadata.grants || [];
        var grantReq = grantsRequests.find( (grantReq) => grantReq.client_id === req.body.client_id && grantReq.api_id === req.body.api_id);
    // Check to see if the ApprovingUser is an owner of this API
        var ownerApis = ApprovingUser.app_metadata.apis || [];
        var apiOwner = ownerApis.find( (api) => api.id === grantReq.api_id);
        if (!grantReq) return Promise.reject({"result":"Grant Not found"});
        if (!apiOwner) return Promise.reject({"result":"Not Api Owner"});
        // Check the scopes requested are available on the API
        var scopesAllowed = grantReq.scopes.every( 
            reqScope => Api.scopes.some( 
                scope => scope.value === reqScope )
            );
        console.log( scopesAllowed);
        
        if (! scopesAllowed ) return { "result": "Scopes Are Not Allowed", "Requested scopes" : grantReq.scopes, "Available Scopes" : Api.scopes };
        // If this is a Scope Update scopes for this or other apis already exist
          console.log("GR::", grantReq);
          if ( grantReq.grant_id ) {
            return getClientGrantById(token, grantReq.grant_id)
              .then( resp => {
                return patchClientGrant(token, grantReq.grant_id, grantReq.scopes);
              })
              .then( resp => {
                return updateUserMetaDataGrants(token, RequestingUser.user_id, grantsRequests, grants, grantReq);
              });
          }
          else { // Create the Client Grant if this is the first time
            return createClientGrant(token, grantReq.client_id, grantReq.scopes, "https://api.iag.com.au/" )
              .then( resp => {
                grantReq.grant_id = resp.id; // add Client Grant Id to grant 
                return updateUserMetaDataGrants(token, RequestingUser.user_id, grantsRequests, grants, grantReq);
            });
          }
          return { "result": "Grant Created" };
    });
  })
  .then( resp => {
    res.json( resp );
  })
  .catch(next);
});

app.get("/getGrants/:client_id", jwtCheck, function(req, res, next) {
  getToken(req.webtaskContext)
  .then( token => {
    return getClientGrantsByClient(token, req.params.client_id);
  })
  .then( resp => {
    res.json( resp );
  })
  .catch(next);
});

app.get("/getAPI/:api_id", jwtCheck, function(req,res, next) {
    getToken(req.webtaskContext)
    .then( token => {
      return getAPI(token, req.params.api_id);
    })
    .then( resp => {
       res.json( resp );
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
          "scopes" : req.body.scopes.map( (scope) => { return {"value": scope}; })
        }
      })
      .then(function(resp) {
        return request.get("https://iag-api.au.auth0.com/api/v2/resource-servers/591a46ade6d8800cc84fdf05",
          {
            headers: { "Authorization": "Bearer " + token },
            json: true
          })
          .then(function(resp) {
            var allscopes = resp.scopes.concat(req.body.scopes.map( (scope) => { return {"value": scope}; }));
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
    .then( token => {
      return getAPIs(token);
    })
    .then( resp => {
      var apis = resp.filter( api => api.identifier != "https://iag-api.au.auth0.com/api/v2/");
      res.json( 
        apis.map( api => {
          return {
            "id": api.id,
            "name": api.name,
            "identifier": api.identifier,
            "scopes" : api.scopes
          };
        })
      );
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
      console.log("storage", data.auth0_mgmt_token);
      if (data.auth0_mgmt_token == null ) { reject("No Token in storage"); return; }
      var storedToken = jwt.decode(data.auth0_mgmt_token, {complete: true});
      jwksClient.getSigningKey(storedToken.header.kid, (err, key) => {  // Get the publicKey of the stored token
        if(err) { reject(err); return; }
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

function getAPI(token, api_id) {
  return request(
          {
            method: "GET",
            url: 'https://iag-api.au.auth0.com/api/v2/resource-servers/' + api_id,
            headers: { "Authorization": "Bearer " + token },
            json: true
          }
        );
}

function getUser(token, user_id) {
  return request.get("https://iag-api.au.auth0.com/api/v2/users/"+ user_id, {
        headers: { "Authorization": "Bearer " + token },
        json: true
    });
}

function getAllClientGrants( token ) {
    return request.get("https://iag-api.au.auth0.com/api/v2/client-grants", {
        headers: { "Authorization": "Bearer " + token },
        qs : { audience: "https://api.iag.com.au/" },
        json: true
        });
}

function getClientGrantById(token, grant_id) {
    return getAllClientGrants( token )
          .then( resp => {
            return resp.filter( grant => { return grant.id == grant_id; });
				  });
}

function getClientGrantsByClient(token, client_id) {
  return  getAllClientGrants( token )
          .then( resp => {
            return resp.filter( grant => { return grant.client_id == client_id; });
  });
}

function patchClientGrant(token, grant_id, scopes) {
  return request({
        method: "PATCH",
        uri: "https://iag-api.au.auth0.com/api/v2/client-grants/" + grant_id,
        headers: { "Authorization": "Bearer " + token },
        body: {
          "scope": scopes
        },
        json: true
      });
}

function createClientGrant(token, client_id, scopes, audience) {
  return request.post("https://iag-api.au.auth0.com/api/v2/client-grants", {
         headers: { "Authorization": "Bearer " + token },
         body: {
          "client_id": client_id,
          "audience": audience,
          "scope": scopes
        },
        json: true
  });
}

function updateUserMetaDataGrantRequests(token, user_id, grantsRequests) {
  return request({
        method: "PATCH",
        headers: { "Authorization": "Bearer " + token },
        uri: "https://iag-api.au.auth0.com/api/v2/users/"+ user_id,
        body: {
          app_metadata: { "grantsRequests": grantsRequests }
        },
        json: true
      });
}

function updateUserMetaDataGrants(token, user_id, grantsRequests, grants, newGrant) {
  //Delete request from array
  grantsRequests.splice(grantsRequests.findIndex( gr => newGrant.id === gr.id), 1);
  //Add it to approved grants
  newGrant.approved = Date.now();
  grants.push(newGrant);
                  
  return request({
    method: "PATCH",
    headers: { "Authorization": "Bearer " + token },
    uri: "https://iag-api.au.auth0.com/api/v2/users/"+ user_id,
    body: {
      app_metadata: {
        "grantsRequests": grantsRequests,
        "grants": grants
      }
    },
    json: true
  });
}

function getClientNameAndSecret(token, client_id) {
  return request.get("https://iag-api.au.auth0.com/api/v2/clients/" + client_id,
  {
    headers: { "Authorization": "Bearer " + token },
    qs: { fields : "name,client_id,client_secret,description" },
    json: true
  });
}


app.use(function(err, req, res, next) {
  console.log("ERROR", err, err.stack);
  res.status(500).send( err.stack);
});

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
    return v.toString(16);
});
}

module.exports = wt.fromExpress(app);









