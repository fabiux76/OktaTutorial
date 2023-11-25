const express = require("express");
const { join } = require("path");
const OktaJwtVerifier = require('@okta/jwt-verifier');

const app = express();

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: 'https://dev-02388022.okta.com/oauth2/default'
});
const audience = 'api://default';

const authenticationRequired = async (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/Bearer (.+)/);
  if (!match) {
    return res.status(401).send();
  }

  try {
    const accessToken = match[1];
    if (!accessToken) {
      return res.status(401, 'Not authorized').send();
    }
    req.jwt = await oktaJwtVerifier.verifyAccessToken(accessToken, audience);
    next();
  } catch (err) {
    return res.status(401).send(err.message);
  }
};


// Serve assets from the /public folder
app.use(express.static(join(__dirname, "public")));

app.get('/api/hello', (req, res) => {
  res.send('Hello world!');
});

app.get('/api/whoami', authenticationRequired, (req, res) => {
  res.json(req.jwt?.claims);
});

// Serve the index page to everything else
app.get("/*", (req, res) => {
  res.sendFile(join(__dirname, "index.html"));
});

// Error handler
app.use(function(err, req, res, next) {
  if (err.name === "UnauthorizedError") {
    return res.status(401).send({ msg: "Invalid token" });
  }

  next(err, req, res);
});

// Listen on port 9000
app.listen(9000, () => console.log("Application running on port 9000"));