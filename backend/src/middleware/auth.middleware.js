// const jwt = require("jsonwebtoken");

// module.exports = function (req, res, next) {
//     const authHeader = req.headers.authorization; // Bearer token

//     if (!authHeader) {
//         return res.status(401).json({ message: "No token provided" });
//     }

//     const token = authHeader.split(" ")[1]; // extract token

//     try {
//         const decoded = jwt.verify(token, process.env.JWT_SECRET);
//         req.user = decoded; // store userId
//         next();
//     } catch (error) {
//         res.status(401).json({ message: "Invalid or expired token" });
//     }
// };

const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const { verifyToken } = require("../utils/jwt");
const User = require("../models/user.model");
const { AppError } = require("./errorHandler.middleware");
const logger = require("../config/logger");

const publicKey = fs.readFileSync(path.join(__dirname, "../../keys/public.pem"), "utf8");

/**
 * Authentication Middleware
 * Verifies JWT signature and expiration on every request
 * Never trusts data solely based on JWT payload; verifies against backend
 */
module.exports = async (req, res, next) => {
    try {
        // Try to get token from Authorization header, cookie, or custom header
        let token = null;
        
        // Check Authorization header (Bearer token)
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(" ")[1];
        }
        
        // Check cookie (for web applications)
        if (!token && req.cookies?.accessToken) {
            token = req.cookies.accessToken;
        }
        
        // Check custom header (for mobile apps)
        if (!token && req.headers['x-access-token']) {
            token = req.headers['x-access-token'];
        }

        if (!token) {
            throw new AppError("No token provided", 401);
        }

        // Verify token signature and expiration
        let decoded;
        try {
            decoded = verifyToken(token);
        } catch (error) {
            logger.warn('Invalid token attempt', { 
                error: error.message, 
                ip: req.ip,
                path: req.path 
            });
            throw new AppError("Invalid or expired token", 401);
        }

        // Verify user still exists and is active (never trust JWT payload alone)
        const user = await User.findById(decoded.id);
        if (!user) {
            throw new AppError("User not found", 401);
        }

        if (!user.isActive) {
            throw new AppError("Account is deactivated", 403);
        }

        // Verify role hasn't changed (additional security check)
        if (user.role !== decoded.role) {
            logger.warn('Role mismatch detected', { 
                userId: user._id, 
                jwtRole: decoded.role, 
                dbRole: user.role 
            });
            // Update token payload with current role
            decoded.role = user.role;
        }

        // Attach user info to request
        req.user = {
            id: decoded.id,
            role: decoded.role,
        };

        next();
    } catch (error) {
        next(error);
    }
};



// const fs = require("fs");
// const path = require("path");
// const jwt = require("jsonwebtoken");

// const publicKey = fs.readFileSync(path.join(__dirname, "../../keys/public.pem"));

// module.exports = function (req, res, next) {
//     const authHeader = req.headers.authorization;

//     if (!authHeader) {
//         return res.status(401).json({ message: "No token provided" });
//     }

//     const token = authHeader.split(" ")[1];

//     try {
//         const decoded = jwt.verify(token, publicKey, {
//             algorithms: ["RS256"]
//         });

//         req.user = decoded;
//         next();
//     } catch (error) {
//         return res.status(401).json({ message: "Invalid or expired token" });
//     }
// };

