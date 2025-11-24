/**
 * Input Validation Middleware
 * Uses Joi for comprehensive input validation and sanitization
 */

const Joi = require('joi');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

// Validation middleware factory
const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true, // Remove unknown fields
      convert: true, // Convert types
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        message: 'Validation error',
        errors,
      });
    }

    // Replace req.body with sanitized and validated data
    req.body = value;
    next();
  };
};

// Validation schemas
const schemas = {
  register: Joi.object({
    name: Joi.string()
      .trim()
      .min(2)
      .max(100)
      .pattern(/^[a-zA-Z\s]+$/)
      .required()
      .messages({
        'string.pattern.base': 'Name must contain only letters and spaces',
      }),
    email: Joi.string()
      .trim()
      .lowercase()
      .email()
      .max(255)
      .required(),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      }),
    role: Joi.string()
      .valid('user', 'manager', 'admin')
      .default('user'),
  }),

  login: Joi.object({
    email: Joi.string()
      .trim()
      .lowercase()
      .email()
      .max(255)
      .required(),
    password: Joi.string()
      .required(),
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string()
      .required(),
  }),

  updateUser: Joi.object({
    name: Joi.string()
      .trim()
      .min(2)
      .max(100)
      .pattern(/^[a-zA-Z\s]+$/),
    email: Joi.string()
      .trim()
      .lowercase()
      .email()
      .max(255),
    role: Joi.string()
      .valid('user', 'manager', 'admin'),
  }).min(1), // At least one field required

  changePassword: Joi.object({
    currentPassword: Joi.string()
      .required(),
    newPassword: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.pattern.base': 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      }),
  }),
};

// XSS protection middleware
const xssProtection = xss();

// MongoDB injection protection
const mongoSanitization = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    // Log sanitization events for monitoring
    console.warn(`Sanitized MongoDB injection attempt: ${key} from IP ${req.ip}`);
  },
});

// HTTP Parameter Pollution protection
const hppProtection = hpp();

// Query parameter validation
const validateQuery = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query, {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
    });

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));

      return res.status(400).json({
        message: 'Query validation error',
        errors,
      });
    }

    req.query = value;
    next();
  };
};

module.exports = {
  validate,
  schemas,
  xssProtection,
  mongoSanitization,
  hppProtection,
  validateQuery,
};

