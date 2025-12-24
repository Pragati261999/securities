/**
 * Secure Task Manager Server
 * Implements comprehensive security measures
 */

const express = require("express");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const connectDB = require("./config/db");
const logger = require("./config/logger");
const fs = require("fs-extra");
const path = require("path");

// Load environment variables
dotenv.config({ path: "./.env" });

// Create Express app
const app = express();

// Trust proxy (for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// ==================== SECURITY MIDDLEWARE ====================

// 1. Security Headers (CSP, HSTS, X-Frame-Options, etc.)
const { securityHeaders, corsOptions, enforceHTTPS } = require("./middleware/security.middleware");
app.use(securityHeaders);
app.use(corsOptions);

// 2. HTTPS Enforcement (in production)
if (process.env.NODE_ENV === 'production') {
  app.use(enforceHTTPS);
}

// 3. Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// 4. Input Validation and Sanitization
const { xssProtection, mongoSanitization, hppProtection } = require("./middleware/validation.middleware");
app.use(xssProtection); // XSS protection
app.use(mongoSanitization); // MongoDB injection protection
app.use(hppProtection); // HTTP Parameter Pollution protection

// 5. Rate Limiting
const { generalLimiter, authLimiter } = require("./middleware/rateLimiter.middleware");
app.use("/api/", generalLimiter); // General API rate limiting
app.use("/api/auth/login", authLimiter); // Stricter rate limiting for auth
app.use("/api/auth/register", authLimiter);

// 6. Request Logging (morgan)
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', {
    stream: {
      write: (message) => logger.info(message.trim())
    }
  }));
}

// ==================== DATABASE CONNECTION ====================
connectDB(process.env.MONGO_URI);

// ==================== API ROUTES ====================
// API Versioning - use /api/v1/ prefix
app.get("/", (req, res) => {
  res.json({ 
    message: "Secure Task Manager API",
    version: "1.0.0",
    documentation: "/api/v1/docs"
  });
});

// Version 1 API routes
app.use("/api/v1/auth", require("./routes/auth.route"));
app.use("/api/v1/user", require("./routes/user.route"));
app.use("/api/v1/upload", require("./routes/upload.route"));

// Legacy routes (redirect to v1)
app.use("/api/auth", require("./routes/auth.route"));
app.use("/api/user", require("./routes/user.route"));
app.use("/api/upload", require("./routes/upload.route"));

// ==================== ERROR HANDLING ====================
const { errorHandler, notFoundHandler } = require("./middleware/errorHandler.middleware");

// 404 handler (must be after all routes)
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

// ==================== SERVER STARTUP ====================
const PORT = process.env.PORT || 5000;

// Ensure logs directory exists
fs.ensureDirSync(path.join(__dirname, '../logs'));

// Ensure uploads directory exists (outside web root)
fs.ensureDirSync(path.join(__dirname, '../uploads'));

// Start server
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`HTTPS Enforcement: ${process.env.NODE_ENV === 'production' ? 'Enabled' : 'Disabled'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

module.exports = app;
