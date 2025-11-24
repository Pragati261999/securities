// const fs = require("fs");
// const path = require("path");
// const jwt = require("jsonwebtoken");

// const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf8");
// const publicKey = fs.readFileSync(path.join(__dirname, "../../keys/public.pem"), "utf8");

// // Sign Access Token (valid for 15 minutes)
// exports.generateAccessToken = (payload) => {
//   return jwt.sign(payload, privateKey, {
//     algorithm: "RS256",
//     expiresIn: "15m",
//   });
// };

// // Sign Refresh Token (valid for 7 days)
// exports.generateRefreshToken = (payload) => {
//   return jwt.sign(payload, privateKey, {
//     algorithm: "RS256",
//     expiresIn: "7d",
//   });
// };

// // Verify Token
// exports.verifyToken = (token) => {
//   return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
// };

const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

// READ KEYS IN UTF-8 (VERY IMPORTANT)
const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf8");
const publicKey = fs.readFileSync(path.join(__dirname, "../../keys/public.pem"), "utf8");

/**
 * Generate Access Token
 * Short-lived token (15 minutes) for API access
 * Uses RS256 algorithm for strong security
 */
exports.generateAccessToken = (payload) => {
    // Ensure payload doesn't contain sensitive information
    const safePayload = {
        id: payload.id,
        role: payload.role,
        // Never include passwords, personal data, or other sensitive info
    };

    return jwt.sign(safePayload, privateKey, {
        algorithm: "RS256", // Strong algorithm - asymmetric encryption
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "15m",
        issuer: process.env.JWT_ISSUER || "secure-task-manager",
        audience: process.env.JWT_AUDIENCE || "secure-task-manager-api",
    });
};

/**
 * Generate Refresh Token
 * Longer-lived token (7 days) for obtaining new access tokens
 * Uses RS256 algorithm and refresh token rotation
 */
exports.generateRefreshToken = (payload) => {
    const safePayload = {
        id: payload.id,
        role: payload.role,
        type: "refresh", // Distinguish from access tokens
    };

    return jwt.sign(safePayload, privateKey, {
        algorithm: "RS256",
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "7d",
        issuer: process.env.JWT_ISSUER || "secure-task-manager",
        audience: process.env.JWT_AUDIENCE || "secure-task-manager-api",
    });
};

/**
 * Verify Token
 * Verifies JWT signature and expiration
 * Only accepts RS256 algorithm (rejects none or weak algorithms)
 */
exports.verifyToken = (token) => {
    try {
        const decoded = jwt.verify(token, publicKey, {
            algorithms: ["RS256"], // Only accept RS256 - reject none, HS256, etc.
            issuer: process.env.JWT_ISSUER || "secure-task-manager",
            audience: process.env.JWT_AUDIENCE || "secure-task-manager-api",
        });

        return decoded;
    } catch (error) {
        // Re-throw with more context
        if (error.name === 'JsonWebTokenError') {
            throw new Error('Invalid token signature');
        } else if (error.name === 'TokenExpiredError') {
            throw new Error('Token expired');
        } else if (error.name === 'NotBeforeError') {
            throw new Error('Token not active yet');
        }
        throw error;
    }
};

