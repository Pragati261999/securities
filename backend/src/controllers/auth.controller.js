const User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const { generateAccessToken, generateRefreshToken, verifyToken } = require("../utils/jwt");
const { trackFailedLogin, resetFailedLogin } = require("../middleware/rateLimiter.middleware");
const { AppError, asyncHandler } = require("../middleware/errorHandler.middleware");
const logger = require("../config/logger");

// Read public key for refresh token verification
const publicKey = fs.readFileSync(path.join(__dirname, "../../keys/public.pem"), "utf8");


// const User = require("../models/user.model");
// const bcrypt = require("bcryptjs");
// const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");

exports.register = asyncHandler(async (req, res) => {
    const { name, email, password, role } = req.body;

    const exist = await User.findOne({ email });
    if (exist) {
        throw new AppError("Email already registered", 400);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
        name,
        email,
        password: hashedPassword,
        role: role || "user"
    });

    // Remove sensitive data from response
    const userResponse = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
    };

    logger.info(`User registered: ${email}`);
    res.status(201).json({ message: "User registered successfully", user: userResponse });
});

exports.login = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        await trackFailedLogin(email);
        throw new AppError("Invalid credentials", 401);
    }

    // Check if account is locked
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
        const remainingMinutes = Math.ceil((user.lockoutUntil - new Date()) / 60000);
        throw new AppError(`Account locked. Please try again in ${remainingMinutes} minute(s).`, 423);
    }

    // Check if account is active
    if (!user.isActive) {
        throw new AppError("Account is deactivated", 403);
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        await trackFailedLogin(email);
        throw new AppError("Invalid credentials", 401);
    }

    // Reset failed login attempts on successful login
    await resetFailedLogin(email);

    const payload = { id: user._id.toString(), role: user.role };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    // Save refresh token and update last login
    user.refreshToken = refreshToken;
    user.lastLogin = new Date();
    user.failedLoginAttempts = 0;
    user.lockoutUntil = null;
    await user.save();

    // Set secure HTTP-only cookies for tokens
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes for access token
    };

    const refreshCookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days for refresh token
    };

    res.cookie('accessToken', accessToken, cookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    logger.info(`User logged in: ${email}`, { userId: user._id, ip: req.ip });

    // Return tokens in response for clients that can't use cookies (mobile apps)
    res.status(200).json({
        message: "Login successful",
        accessToken,
        refreshToken,
    });
});

exports.refresh = asyncHandler(async (req, res) => {
    // Try to get refresh token from body, cookie, or header
    const refreshToken = req.body.refreshToken || req.cookies?.refreshToken || req.headers['x-refresh-token'];
    
    if (!refreshToken) {
        throw new AppError("Missing refresh token", 401);
    }

    // 1️⃣ Check if refresh token exists in DB (prevents use of revoked tokens)
    const user = await User.findOne({ refreshToken });
    if (!user) {
        logger.warn('Invalid refresh token attempt', { ip: req.ip });
        throw new AppError("Invalid refresh token", 403);
    }

    // Check if account is active
    if (!user.isActive) {
        throw new AppError("Account is deactivated", 403);
    }

    // 2️⃣ Verify signature and expiration
    let decoded;
    try {
        decoded = verifyToken(refreshToken);
    } catch (err) {
        // Token invalid or expired - revoke it
        user.refreshToken = null;
        await user.save();
        throw new AppError("Invalid or expired refresh token", 403);
    }

    // 3️⃣ Verify token matches user
    if (decoded.id !== user._id.toString()) {
        throw new AppError("Token mismatch", 403);
    }

    // 4️⃣ REFRESH TOKEN ROTATION - generate new tokens
    const payload = { id: user._id.toString(), role: user.role };
    const newAccessToken = generateAccessToken(payload);
    const newRefreshToken = generateRefreshToken(payload);

    // Replace the old refresh token (ROTATION - prevents replay attacks)
    user.refreshToken = newRefreshToken;
    await user.save();

    // Set secure cookies
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000,
    };

    const refreshCookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
    };

    res.cookie('accessToken', newAccessToken, cookieOptions);
    res.cookie('refreshToken', newRefreshToken, refreshCookieOptions);

    logger.info(`Token refreshed for user: ${user._id}`);

    res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
    });
});
exports.logout = asyncHandler(async (req, res) => {
    // Get refresh token from body, cookie, or header
    const refreshToken = req.body.refreshToken || req.cookies?.refreshToken || req.headers['x-refresh-token'];
    
    if (refreshToken) {
        const user = await User.findOne({ refreshToken });
        if (user) {
            user.refreshToken = null; // Revoke token immediately
            await user.save();
            logger.info(`User logged out: ${user._id}`);
        }
    }

    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.json({ message: "Logged out successfully" });
});



// exports.generateToken = (user) => {
//     return jwt.sign(
//         { id: user._id },
//         privateKey,
//         {
//             algorithm: "RS256",
//             expiresIn: process.env.JWT_EXPIRES_IN || "1d"
//         }
//     );
// };

// exports.register = async (req, res) => {
//     try {
//         const { name, email, password, role } = req.body;

//         // check if email exists
//         const exist = await User.findOne({ email });
//         if (exist) return res.status(400).json({ message: "Email already registered" });

//         // hash password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // create user
//         const user = await User.create({
//             name,
//             email,
//             password: hashedPassword,
//             role: role || "user"  // default user

//         });

//         res.status(201).json({ message: "User registered", user });
//     } catch (error) {
//         res.status(500).json({ message: error.message });
//     }
// };

// exports.login = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         // user exists?
//         const user = await User.findOne({ email });
//         if (!user) return res.status(400).json({ message: "Invalid credentials" });

//         // match password
//         const valid = await bcrypt.compare(password, user.password);
//         if (!valid) return res.status(400).json({ message: "Invalid credentials" });

//         const payload = { id: user._id, role: user.role };

//         const accessToken = generateAccessToken(payload);
//         const refreshToken = generateRefreshToken(payload);


//         res.status(200).json({
//             message: "Login successful",
//             accessToken,
//             refreshToken,
//         });

//     } catch (error) {
//         res.status(500).json({ message: error.message });
//     }
// };
