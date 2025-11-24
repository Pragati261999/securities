/**
 * Logger Configuration
 * Secure logging that filters sensitive information
 */

const winston = require('winston');
const path = require('path');

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

// Filter sensitive information from logs
const sensitiveDataFilter = winston.format((info) => {
  // Remove sensitive fields
  const sensitiveFields = ['password', 'token', 'refreshToken', 'accessToken', 'authorization', 'jwt'];
  
  if (info.message) {
    // Remove JWT tokens from log messages
    info.message = info.message.replace(/Bearer\s+[\w\-._~+/]+/gi, 'Bearer [REDACTED]');
    info.message = info.message.replace(/token["\s:=]+[\w\-._~+/]+/gi, 'token [REDACTED]');
  }
  
  // Remove sensitive fields from metadata
  if (info.meta) {
    sensitiveFields.forEach(field => {
      if (info.meta[field]) {
        info.meta[field] = '[REDACTED]';
      }
    });
  }
  
  return info;
});

// Create logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    sensitiveDataFilter(),
    logFormat
  ),
  defaultMeta: { service: 'secure-task-manager' },
  transports: [
    // Write all logs to console
    new winston.transports.Console({
      format: process.env.NODE_ENV === 'production' 
        ? winston.format.combine(sensitiveDataFilter(), logFormat)
        : consoleFormat,
    }),
    // Write errors to error.log
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // Write all logs to combined.log
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
  // Handle exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/exceptions.log'),
    }),
  ],
  // Handle promise rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/rejections.log'),
    }),
  ],
});

// Security event logging helper
logger.security = (event, details) => {
  logger.warn(`[SECURITY] ${event}`, {
    ...details,
    timestamp: new Date().toISOString(),
  });
};

module.exports = logger;

