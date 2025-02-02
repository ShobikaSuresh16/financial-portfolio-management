const jwt = require("jsonwebtoken");

// Use the same secret key as in server.js
const SECRET_KEY = "Shobika&16";

function authenticateToken(req, res, next) {
    // Get the token from the Authorization header
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract token (Bearer <token> format)

    if (!token) return res.status(401).send("Access denied. No token provided.");

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send("Invalid token.");
        req.user = user; // Add user data (decoded token) to the request object
        next();
    });
}

module.exports = authenticateToken;
