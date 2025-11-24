/**
 * Error Handling Middleware
 * Prevents information leakage and provides secure error responses
 */

const logger = require('../config/logger');

// Custom error class
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Generic error handler
const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || 500;
  let message = 'An error occurred';

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  } else if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation error';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (err.code === 11000) {
    // MongoDB duplicate key error
    statusCode = 400;
    message = 'Duplicate entry';
  } else if (err.isOperational) {
    message = err.message;
  }

  // Log error details (server-side only)
  const errorDetails = {
    message: err.message,
    stack: err.stack,
    statusCode,
    path: req.path,
    method: req.method,
    ip: req.ip,
    user: req.user?.id || 'anonymous',
    timestamp: new Date().toISOString(),
  };

  // Log authentication failures and security events
  if (statusCode === 401 || statusCode === 403) {
    logger.warn('Authentication/Authorization failure', errorDetails);
  } else if (statusCode >= 500) {
    logger.error('Server error', errorDetails);
  } else {
    logger.info('Client error', errorDetails);
  }

  // Remove sensitive information from response
  const response = {
    message,
    ...(process.env.NODE_ENV === 'development' && {
      // Only show stack trace in development
      stack: err.stack,
    }),
  };

  res.status(statusCode).json(response);
};

// 404 handler
const notFoundHandler = (req, res, next) => {
  const err = new AppError(`Route ${req.originalUrl} not found`, 404);
  next(err);
};

// Async error wrapper
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

module.exports = {
  AppError,
  errorHandler,
  notFoundHandler,
  asyncHandler,
};

