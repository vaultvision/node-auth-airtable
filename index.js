const debug = require('debug')('auth-example:server');
const path = require("path");
const http = require('http');

const express = require('express');
const logger = require('morgan');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const openidClient = require("openid-client");
const jwt = require('jsonwebtoken');
const fetch = require("node-fetch");

// Config
require("dotenv").config();
const config = {
    "SESSION_SECRET": process.env.SESSION_SECRET,
    "BASE_URL": process.env.BASE_URL,
    "VV_ISSUER_URL": process.env.VV_ISSUER_URL,
    "VV_CLIENT_ID": process.env.VV_CLIENT_ID,
    "VV_CLIENT_SECRET": process.env.VV_CLIENT_SECRET,
    "PROXY_TARGET_URL": process.env.PROXY_TARGET_URL || "https://api.airtable.com",
    "AIR_TABLE_API_TOKEN": process.env.AIR_TABLE_API_TOKEN,
    "FRONT_SITE_URL": process.env.FRONT_SITE_URL,
};

const oidcCallbackUrl = new URL('/oidc/callback', config.BASE_URL).toString();
const oidcLogoutUrl = new URL('/oidc/logout', config.BASE_URL).toString();

let _oidcClient;
function getOidcClient() {
    return new Promise((resolve, reject) => {
        if (_oidcClient) {
            resolve(_oidcClient);
            return;
        }

        const cbResolve = (iss) => {
            _oidcClient = new iss.Client({
                client_id: config.VV_CLIENT_ID,
                client_secret: config.VV_CLIENT_SECRET,
                redirect_uris: [oidcCallbackUrl],
                response_types: ['code'],
            });
            resolve(_oidcClient);
        }
        const cbError = (err) => {
            console.log("getOidcClientError:", err);
            reject(err);
        }
        openidClient.Issuer.discover(config.VV_ISSUER_URL)
            .then(cbResolve)
            .catch(cbError);
    });
}

const app = express();
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const cookieOptions = {
            secure: true,
            httpOnly: true,
            sameSite: 'none'
        };

var enableCors = function(req, res) {
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers');
  res.setHeader('Access-Control-Max-Age', 60 * 60 * 24 * 30);
  res.setHeader('Allow', 'GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH');
};

//////////////////////////////////
function verifyLookupJWT(jwtStr){
  return p = new Promise((resolve, reject)=>{
    jwt.verify(
      jwtStr,
      config.SESSION_SECRET,
      { algorithms: ['HS256'] },
      function (err, decoded) {
          console.log("err", err);
          console.log("decoded", decoded);
          if (err) {
            reject(err);
          } else {
            resolve(decoded);
          }
      }
    );
  })
}

function validateJWT(req){
  //check in cookie first
  const jwt_from_cookie = req.cookies.authjwt;

  //check in Authorize header second
  const jwt_from_header = req.headers.authorization;
  // if it is a Bearer token strip out "Bearer"
  if (jwt_from_header && jwt_from_header.toLowerCase().startsWith("bearer ")) {
    jwt_from_header = jwt_from_header.split(" ")[1];
  }

  //pick the cookie jwt first
  let jwtStr = "";
  if (jwt_from_cookie) {
    jwtStr = jwt_from_cookie;
  } else if (jwt_from_header) {
    jwtStr = jwt_from_header;
  }
  console.log("jwtStr", jwtStr);

  //Verify JWT
  return verifyLookupJWT(jwtStr)
  .then((verifyRes)=>{
    console.log("verifyRes", verifyRes);
    return verifyRes;
  })
  .catch((err)=>{
    throw err;
  })
  
}

app.options("/*", function (req, res, next) {
    enableCors(req, res);
    res.json({});
})

app.get('/session/jwt', function (req, res, next) {
    if (req.cookies.authjwt) {
        res.json({
            result: true,
            authjwt: req.cookies.authjwt,
        });
    } else {
        res.json({
            result: false,
        });
    }
});


app.get('/login', (req, res) => {
    res.redirect('/oidc/login');
})

// /oidc/login kicks off the OIDC flow by redirecting to Vault Vision. Once
// authentication is complete the user will be returned to /oidc/callback.
app.get('/oidc/login', (req, res) => {
    getOidcClient().then((oidcClient) => {
        const gens = openidClient.generators;
        const nonce = gens.nonce();
        const state = gens.state();
        const codeVerifier = gens.codeVerifier();
        const codeChallenger = gens.codeChallenge(codeVerifier);

        res.cookie("code_verifier", codeVerifier, cookieOptions);
        res.cookie("nonce", nonce, cookieOptions);
        res.cookie("state", state, cookieOptions);

        const redir = oidcClient.authorizationUrl({
            scope: 'openid email profile',
            resource: oidcCallbackUrl,
            code_challenge: codeChallenger,
            code_challenge_method: 'S256',
            nonce: nonce,
            state: state,
        });
        res.redirect(redir);
    }).catch((err) => {
        res.redirect(config.FRONT_SITE_URL);
    });
});

// Once Vault Vision authenticates a user they will be sent here to complete
// the OIDC flow.
app.get('/oidc/callback', (req, res) => {
    getOidcClient().then((oidcClient) => {
        const oidcParams = oidcClient.callbackParams(req);
        oidcClient.callback(oidcCallbackUrl, oidcParams, {
            code_verifier: req.cookies.code_verifier,
            state: req.cookies.state,
            nonce: req.cookies.nonce,
        }).then((tokenSet) => {
            res.clearCookie("code_verifier");
            res.clearCookie("state");
            res.clearCookie("nonce");
            if (tokenSet.access_token) {
                oidcClient.userinfo(tokenSet.access_token).then((userinfo) => {


                  // Create token
                  const token = jwt.sign(
                    userinfo,
                    config.SESSION_SECRET,
                    {
                      expiresIn: "24h",
                      algorithm: 'HS256',
                    }
                  );
                  res.cookie("authjwt", token, cookieOptions);
                  res.redirect(config.FRONT_SITE_URL);

                });
            } else {
                res.redirect(config.FRONT_SITE_URL);
            }
        });
    }).catch((err) => {
        console.log(err);
        res.redirect(config.FRONT_SITE_URL);
    });
});

// Logout clears the cookies and then sends the users to Vault Vision to clear
// the cookie, then Vault Vision will redirect the user to /auth/logout.
app.get('/logout', (req, res, next) => {
  res.clearCookie("authjwt");

  const u = new URL('/logout', config.VV_ISSUER_URL);
  u.searchParams.set('client_id', config.VV_CLIENT_ID);
  u.searchParams.set('return_to', oidcLogoutUrl);
  res.redirect(u.toString());

});

app.get('/oidc/logout', (req, res) => {
    res.redirect(config.FRONT_SITE_URL);
});

//Single record
app.get('/v0/:baseid/:table/:record', (req, res) => {
    enableCors(req, res);
    let vv_id="";
    validateJWT(req)
    .then((validUser)=>{
      vv_id = validUser.sub;

      const qs = new URLSearchParams(req.query);
      recordOwnedByvv_id(`/v0/${req.params.baseid}/${req.params.table}/${req.params.record}?${qs}`, vv_id)
      .then((owned)=>{
        if (owned.id) {
          res.status(200);
          res.send(JSON.stringify(owned));
        } else {
          res.status(401);
          res.send(JSON.stringify({"error":"401 Unauthorized"}));
        }      
      })
      .catch(err=>{throw err})
    })
    .catch((err)=>{
      res.status(401);
      res.send(JSON.stringify({"error":"401 Unauthorized"}));
    })   
});

//LIST
app.get('/v0/:baseid/:table', (req, res) => {
  console.log("req.cookies.authjwt", req.cookies.authjwt);
  enableCors(req, res);
  let vv_id="";
  validateJWT(req)
  .then((validUser)=>{
    vv_id = validUser.sub;

    let filterByFormula=req.query.filterByFormula;
    let newfilter = "";
    let newPath = "";
    if (filterByFormula) {
      //AND(expr, {vv_id}="xxxxx") 
      newfilter = `AND(${filterByFormula}, {vv_id}="${vv_id}")`;
    } else {
      //{vv_id}="xxxxxxxx"
      newfilter = `{vv_id}="${vv_id}"`;
    }

    const newParams = JSON.parse(JSON.stringify(req.query));
    newParams["filterByFormula"] = newfilter;
    const qs = new URLSearchParams(newParams);

    fetch(config.PROXY_TARGET_URL + req.path + '?' + qs, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + config.AIR_TABLE_API_TOKEN
      }
    })
    .then((data)=>{
      return data.json();
    })
    .then(json=>{
      //TODO check different status to return errors if they happened
      res.status(200);
      res.send(json);
    })
    .catch(err=>{throw err})
  })
  .catch((err)=>{
    console.log("err", err);
    res.status(401);
    res.send(JSON.stringify({"error":"401 Unauthorized"}));
  })   
});


//CREATE
app.post('/v0/:baseid/:table', (req, res) => {
  enableCors(req, res);
  let vv_id="";
  validateJWT(req)
  .then((validUser)=>{
    vv_id = validUser.sub;

    const newBody = JSON.parse(JSON.stringify(req.body));
    if (newBody.records && newBody.records.length > 0) {
      newBody.records.forEach(record=>{
        record.fields["vv_id"]=vv_id;
      })
    } else if (newBody.fields) {
      newBody.fields["vv_id"]=vv_id;
    } else {
      res.status(400);
      res.send(JSON.stringify({"error":"400 Invalid Request No Records or Fields Submitted"}));
      return
    }
    
    fetch(config.PROXY_TARGET_URL + req.path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + config.AIR_TABLE_API_TOKEN
      },
      body: JSON.stringify(newBody)
    })
    .then((data)=>{
      return data.json();
    })
    .then(json=>{
      //TODO check different status to return errors if they happened
      res.status(200);
      res.send(json);
    })
    .catch(err=>{throw err})
  })
  .catch((err)=>{
    console.log("err", err);
    res.status(401);
    res.send(JSON.stringify({"error":"401 Unauthorized"}));
  })   

});


function putUpsert(req, res, next){
  Upsert(req, res, next, "PUT");
}
function patchUpsert(req, res, next){
  Upsert(req, res, next, "PATCH");
}

function Upsert(req, res, next, method){
  enableCors(req, res);
  let vv_id="";
  validateJWT(req)
  .then((validUser)=>{
    vv_id = validUser.sub;

    const newBody = JSON.parse(JSON.stringify(req.body));

    //don't allow single field updates, this could allow a user to override a vv_id
    if (newBody.fields) {
      res.status(400);
      res.send(JSON.stringify({"error":"400 Invalid Request Only upsert is support with records[]; single fields is not supported"}));
      return;
    }
    
    if (newBody.records && newBody.records.length > 0) {
      newBody["performUpsert"]={"fieldsToMergeOn":["vv_id"]};
      newBody.records.forEach(record=>{
        record.fields["vv_id"]=vv_id;
      })
    } else {
      res.status(400);
      res.send(JSON.stringify({"error":"400 Invalid Request No Records"}));
      return
    }

    fetch(config.PROXY_TARGET_URL + req.path, {
      "method": method,
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + config.AIR_TABLE_API_TOKEN
      },
      body: JSON.stringify(newBody)
    })
    .then((data)=>{
      return data.json();
    })
    .then(json=>{
      //TODO check different status to return errors if they happened
      console.log("json", json);
      res.status(200);
      res.send(json);
    })
    .catch(err=>{throw err})
  })
  .catch((err)=>{
    console.log("err", err);
    res.status(401);
    res.send(JSON.stringify({"error":"401 Unauthorized"}));
  }) 
}

//Update or Insert - Upsert
app.put('/v0/:baseid/:table', putUpsert);
app.patch('/v0/:baseid/:table', patchUpsert);


// basic error handlers
app.use(function (req, res, next) {
    next(createError(404));
});

app.use(function (err, req, res, next) {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    res.status(err.status || 500);
    res.json({
        message: err.message,
        error: err
    });
});

app.listen(process.env.PORT || 3000)

function recordOwnedByvv_id(path, vv_id){
  // return new Promise((resolve, reject)=>{
  //   resolve(true);
  // })
  return fetch(config.PROXY_TARGET_URL + path, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + config.AIR_TABLE_API_TOKEN
    }
  })
  .then(res=>res.json())
  .then(res=>{
    console.log("owend by id res.records: ", res);
    if (res.fields && res.fields.vv_id && res.fields.vv_id==vv_id) {
      return res;
    } else {
      return {};
      //return new Promise((resolve, reject)=>{reject("401 Unauthorized")});
      //throw new Error("401 Unauthorized");
    }
  })
  .catch(err=>{throw err})
}
