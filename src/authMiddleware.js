// authMiddleware.js
// This file contains the middleware for verifying AWS Cognito JWTs.

// --- Dependencies ---
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// --- Cognito Configuration ---
// IMPORTANT: You must replace these placeholder values with your actual
// AWS Cognito User Pool details. You can find these in your .env file
// or directly here for simplicity during setup.
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'YOUR_USER_POOL_ID';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';

// Create a JWKS (JSON Web Key Set) client
// This client will download the public keys from Cognito, which are used to
// verify the signature of the JWTs.
const client = jwksClient({
  jwksUri: `https://cognito-idp.${AWS_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`
});

// This function is required by the 'jsonwebtoken' library.
// It retrieves the correct signing key from the JWKS based on the key ID
// found in the JWT header (kid).
function getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
        callback(err);
        return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// --- The Middleware Function ---
const authorizationMiddleware = (req, res, next) => {
  // Check if the Authorization header exists and is in the correct format
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access Denied: No token provided or malformed header.' });
  }

  // Extract the token from the "Bearer <token>" string
  const token = authHeader.split(' ')[1];

  // Verify the token using the public key from Cognito
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error("JWT Verification Error:", err);
      return res.status(401).json({ message: 'Access Denied: Invalid or expired token.' });
    }

    // If the token is valid, the 'decoded' payload is attached to the request object.
    // This makes the user's information (like their unique Cognito ID, 'sub')
    // available to the main route logic.
    req.user = decoded;
    
    // Pass control to the next middleware or the main route handler
    next();
  });
};

// Export the middleware so it can be used in server.js
module.exports = authorizationMiddleware;

