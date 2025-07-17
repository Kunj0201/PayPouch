// authMiddleware.js
// This file contains the middleware for verifying AWS Cognito JWTs.
// This version corrects the "jwksUri is not defined" reference error.

// --- Dependencies ---
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
require('dotenv').config();

// --- Cognito Configuration ---
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const AWS_REGION = process.env.AWS_REGION;

// ** FIX: Check if the required environment variables are set **
if (!COGNITO_USER_POOL_ID || !AWS_REGION) {
    throw new Error('Cognito User Pool ID and AWS Region must be set in the .env file');
}

// ** FIX: Define jwksUri BEFORE it is used. **
const jwksUri = `https://cognito-idp.${AWS_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`;

// Log the URI to help with debugging connection issues.
console.log(`[Auth Middleware] JWKS URI configured to: ${jwksUri}`);

// Create a JWKS (JSON Web Key Set) client **ONCE**.
const client = jwksClient({
  jwksUri: jwksUri
});

// This function retrieves the correct signing key from Cognito.
function getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
        console.error("Error getting signing key:", err);
        callback(err);
        return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// --- The Middleware Function ---
const authorizationMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access Denied: No token provided or malformed header.' });
  }

  const token = authHeader.split(' ')[1];

  // Verify the token using the public key from Cognito
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error("JWT Verification Error:", err);
      return res.status(401).json({ message: 'Access Denied: Invalid or expired token.' });
    }

    // Attach the decoded user information to the request object
    req.user = decoded;
    
    // Proceed to the next function in the chain
    next();
  });
};

module.exports = authorizationMiddleware;

