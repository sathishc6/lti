const express = require('express');
const bodyParser = require('body-parser');
const jose = require('jose');
const { generateKeyPair, JWKS, SignJWT, jwtVerify, createRemoteJWKSet } = require('jose');
const axios = require('axios');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

let privateKey;
let publicKey;
let jwks;

async function generateKeys() {
  try {
    const { publicKey: pubKey, privateKey: privKey } = await generateKeyPair('RS256');
    privateKey = privKey;
    publicKey = pubKey;
    console.log('Keys generated successfully');
  } catch (err) {
    console.error('Error generating keys:', err);
    throw err;
  }
}

async function generateJWKS() {
  try {
    const keyStore = new JWKS.KeyStore();
    keyStore.add(publicKey); // Add public key to JWKS

    jwks = keyStore.toJWKS(true); // Convert to JWKS format
    console.log('JWKS:', jwks);
  } catch (err) {
    console.error('Error generating JWKS:', err);
    throw err;
  }
}

generateKeys().then(generateJWKS).catch(err => {
  console.error('Error during setup:', err);
});

// JWKS endpoint
app.get('/jwks', (req, res) => {
  res.json(jwks);
});

// OIDC login initiation endpoint
app.get('/oidc-login', (req, res) => {
  const iss = req.query.iss; // LMS platform issuer URL
  const clientId = '3ab57645-e04b-4f54-bf6b-bf54c164c40b'; // Replace with your client ID
  const redirectUri = 'http://localhost:3000/oidc-callback'; // Replace with your OIDC callback URL
  const loginHint = req.query.login_hint;
  const ltiMessageHint = req.query.lti_message_hint;

  const authorizationEndpoint = `${iss}/auth`; // LMS authorization endpoint
  const state = 'some-random-state'; // Generate a secure random state

  const authorizationUrl = `${authorizationEndpoint}?client_id=${clientId}&response_type=id_token&scope=openid&redirect_uri=${redirectUri}&state=${state}&login_hint=${loginHint}&lti_message_hint=${ltiMessageHint}&response_mode=form_post&prompt=none`;

  res.redirect(authorizationUrl);
});

// OIDC callback handling
app.post('/oidc-callback', async (req, res) => {
  const id_token = req.body.id_token;
  const jwksUrl = 'http://localhost:3000/jwks'; // Replace with your JWKS URL

  try {
    const JWKS = createRemoteJWKSet(new URL(jwksUrl));
    const { payload } = await jwtVerify(id_token, JWKS);
    console.log('Verified payload:', payload);

    // Extract LTI claims from the payload
    const userId = payload.sub;
    const roles = payload['https://purl.imsglobal.org/spec/lti/claim/roles'];
    const context = payload['https://purl.imsglobal.org/spec/lti/claim/context'];
    const resourceLink = payload['https://purl.imsglobal.org/spec/lti/claim/resource_link'];

    // Obtain the access token
    const tokenResponse = await axios.post('https://auth.brightspace.com/oauth2/auth', {
      grant_type: 'client_credentials',
      client_id: '3ab57645-e04b-4f54-bf6b-bf54c164c40b', // Replace with your client ID
      client_secret: 'INwvnsm0Hc3aDmTfm3l9Rd9urhZ7kbiYj7HBfuHkC0A', // Replace with your client secret
      scope: 'content:*:* core:*:* datahub:*:* enrollment:*:* grades:*:* organizations:*:* quizzing:*:* reporting:*:* users:*:*' // Specify the necessary scopes
    });

    const accessToken = tokenResponse.data.access_token;

    // Call Brightspace API
    const userResponse = await axios.get('https://acadlms.d2l-partners.brightspace.com/d2l/api/lp/1.43/users/whoami', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const userData = userResponse.data;

    res.send(`<h1>Welcome, user ${userId}!</h1><p>Roles: ${roles}</p><p>Context: ${context}</p><p>Resource Link: ${resourceLink}</p><p>User Data: ${JSON.stringify(userData)}</p>`);
  } catch (err) {
    console.error('Error processing OIDC callback:', err);
    res.status(401).send('Invalid token');
  }
});

// Signing a JWT (for example purposes)
async function signToken(privateKey, payload) {
  try {
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(privateKey);

    console.log('Signed JWT:', jwt);
    return jwt;
  } catch (err) {
    console.error('Error signing token:', err);
    throw err;
  }
}

// Example usage of signing a JWT
app.get('/sign-jwt', async (req, res) => {
  const payload = {
    sub: '1234567890',
    name: 'John Doe',
    admin: true
  };

  try {
    const token = await signToken(privateKey, payload);
    res.send(`Signed JWT: ${token}`);
  } catch (err) {
    res.status(500).send('Error signing token');
  }
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
