require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const bodyParser = require('body-parser');
const port = 3001;
const users = require('./users.json');

// Authorization middleware. When used, the
// Access Token must exist and be verified against
// the Auth0 JSON Web Key Set
const checkJwt = jwt({
  // Dynamically provide a signing key
  // based on the kid in the header and 
  // the signing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${process.env.AUTH0_TENANT}.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
  audience: `${process.env.AUTH0_API_AUDIENCE}`,
  issuer: `${process.env.AUTH0_TENANT}`,
  algorithms: ['RS256']
});

app.use(bodyParser.json({ extended: true }));

app.post('/api/v1/users/verify', checkJwt, function (req, res) {
  const user = users.find(u => u.email === req.body.email);
  if (user) {
    if (user.password === req.body.password) {
      res.status(200).json({
        credentialsValid: true,
      });
    } else {
      res.status(200).json({
        credentialsValid: false,
      });
    }
  } else {
    res.status(404).json({
      message: 'User not found.'
    });
  }
});

app.get('/api/v1/users/:email', checkJwt, function (req, res) {
  const user = users.find(u => u.email === req.body.email);

  if (user) {
    res.status(200).json({
      nickname: user.username,
      fullName: user.fullName
    });
  } else {
    res.status(404).json({
      message: `User with the email address ${req.params.email} not found.`
    });
  }
});

app.get('/api/v1/users/:email/accessControl/:organisation_id?', function (req, res) {
  const user = users.find(u => u.email === req.params.email);

  if (user) {
    res.status(200).json({
      "hasAccessToProduct": user.hasAccessToProduct,
      "isEnabledAgainstProduct": user.isEnabledAgainstProduct,
      "productSpecificId": user.productSpecificId,
      "productSpecificClaims": user.productSpecificClaims
    });
  } else {
    res.status(404).json({
      message: `User with the email address ${req.params.email} not found.`
    });
  }
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})