/**
 * Rate Limiting Middleware
 * Implements rate limiting with account lockout and CAPTCHA support
 */

const rateLimit = require('express-rate-limit');
const User = require('../models/user.model');

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    message: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    res.status(429).json({
      message: 'Too many requests from this IP, please try again later.',
    });
  },
});

// Strict rate limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: {
    message: 'Too many login attempts, please try again later.',
  },
  skipSuccessfulRequests: true, // Don't count successful requests
  handler: async (req, res) => {
    // Log failed attempt
    const ip = req.ip || req.connection.remoteAddress;
    console.warn(`Rate limit exceeded for authentication from IP: ${ip}`);
    
    res.status(429).json({
      message: 'Too many login attempts, please try again later.',
    });
  },
});

// Account lockout middleware
const accountLockout = async (req, res, next) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return next();
    }

    const user = await User.findOne({ email });
    
    if (user && user.failedLoginAttempts >= 5) {
      const lockoutTime = user.lockoutUntil || new Date();
      
      if (lockoutTime > new Date()) {
        const remainingMinutes = Math.ceil((lockoutTime - new Date()) / 60000);
        return res.status(423).json({
          message: `Account locked due to multiple failed login attempts. Please try again in ${remainingMinutes} minute(s).`,
        });
      } else {
        // Lockout period expired, reset attempts
        user.failedLoginAttempts = 0;
        user.lockoutUntil = null;
        await user.save();
      }
    }

    next();
  } catch (error) {
    next();
  }
};

// Track failed login attempts
const trackFailedLogin = async (email) => {
  try {
    const user = await User.findOne({ email });
    
    if (user) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      
      if (user.failedLoginAttempts >= 5) {
        // Lock account for 30 minutes
        user.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      }
      
      await user.save();
    }
  } catch (error) {
    console.error('Error tracking failed login:', error);
  }
};

// Reset failed login attempts on successful login
const resetFailedLogin = async (email) => {
  try {
    const user = await User.findOne({ email });
    
    if (user) {
      user.failedLoginAttempts = 0;
      user.lockoutUntil = null;
      await user.save();
    }
  } catch (error) {
    console.error('Error resetting failed login:', error);
  }
};

// CAPTCHA verification middleware (placeholder - integrate with actual CAPTCHA service)
const verifyCaptcha = async (req, res, next) => {
  // Skip CAPTCHA in development
  if (process.env.NODE_ENV === 'development') {
    return next();
  }

  const { captchaToken } = req.body;
  
  if (!captchaToken) {
    return res.status(400).json({
      message: 'CAPTCHA verification required',
    });
  }

  // TODO: Integrate with actual CAPTCHA service (Google reCAPTCHA, hCaptcha, etc.)
  // For now, this is a placeholder
  // Example: const isValid = await verifyWithCaptchaService(captchaToken);
  
  next();
};

module.exports = {
  generalLimiter,
  authLimiter,
  accountLockout,
  trackFailedLogin,
  resetFailedLogin,
  verifyCaptcha,
};

