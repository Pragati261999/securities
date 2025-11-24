# Security Implementation Guide

This document explains the comprehensive security measures implemented in the Secure Task Manager API.

## 1. Authentication and Authorization

### JWT Implementation
- **Algorithm**: RS256 (asymmetric encryption) - strong and secure
- **Why RS256?**: Uses public/private key pair, making it impossible to forge tokens without the private key
- **Token Types**:
  - **Access Token**: Short-lived (15 minutes) for API access
  - **Refresh Token**: Longer-lived (7 days) for obtaining new access tokens

### Token Verification
- **Every Request**: JWT signature and expiration are verified on every protected route
- **Backend Verification**: Never trusts JWT payload alone - always verifies against database
- **User Status Check**: Verifies user exists, is active, and role matches

### Role-Based Access Control (RBAC)
- **Roles**: `user`, `manager`, `admin`
- **Implementation**: Middleware checks user role before allowing access
- **Usage**: `authorize('admin', 'manager')` - allows multiple roles

### Security Features
- No sensitive data in JWT payload (no passwords, personal data)
- Token rotation on refresh (prevents replay attacks)
- Immediate token revocation on logout

## 2. Token Management

### Short-Lived Access Tokens
- **Duration**: 15 minutes
- **Purpose**: Minimize damage if token is compromised
- **Storage**: HttpOnly, Secure, SameSite cookies (web) or secure storage (mobile)

### Refresh Token Rotation
- **How it works**: When refresh token is used, a new one is generated and the old one is invalidated
- **Why**: Prevents replay attacks - if a refresh token is stolen, it can only be used once
- **Storage**: Database (for revocation tracking)

### Token Revocation
- **On Logout**: Refresh token is immediately removed from database
- **On Account Compromise**: All tokens can be invalidated by clearing refresh tokens

### Secure Storage
- **Web Applications**: HttpOnly cookies (prevents XSS access)
- **Mobile Applications**: Secure keychain/keystore
- **Never**: LocalStorage, sessionStorage, or URL parameters

## 3. Input Validation and Data Handling

### Joi Validation
- **Comprehensive**: All input is validated using Joi schemas
- **Type Checking**: Enforces correct data types
- **Length Limits**: Prevents buffer overflow attacks
- **Format Validation**: Email, password strength, etc.

### Sanitization
- **XSS Protection**: `xss-clean` sanitizes all output
- **MongoDB Injection**: `express-mongo-sanitize` prevents NoSQL injection
- **Parameter Pollution**: `hpp` prevents HTTP parameter pollution

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## 4. Data Protection

### HTTPS/TLS
- **Enforcement**: Automatic redirect to HTTPS in production
- **Headers**: Strict-Transport-Security (HSTS) forces HTTPS for 1 year
- **Why**: Encrypts all data in transit, preventing man-in-the-middle attacks

### Encryption at Rest
- **Passwords**: Hashed using bcrypt (10 rounds)
- **Sensitive Data**: Should be encrypted using AES-256 before storage
- **Database**: Use encrypted database connections

### Secret Management
- **RSA Keys**: Stored in `keys/` directory (private key never committed)
- **Environment Variables**: All secrets in `.env` file (not in code)
- **Production**: Use AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault

## 5. Error Handling and Logging

### Generic Error Messages
- **Client**: Only receives generic messages ("Invalid credentials", "Access denied")
- **Server**: Detailed errors logged server-side only
- **Why**: Prevents information leakage that could help attackers

### Security Event Logging
- **Authentication Failures**: Logged with IP address and timestamp
- **Invalid Token Attempts**: Tracked for monitoring
- **Access Violations**: Logged for audit trail

### Sensitive Data Filtering
- **Logs**: Automatically filter out passwords, tokens, JWTs
- **Pattern Matching**: Removes JWT tokens from log messages
- **Compliance**: Helps meet GDPR and security audit requirements

## 6. Rate Limiting

### General API Rate Limiting
- **Limit**: 100 requests per 15 minutes per IP
- **Purpose**: Prevents abuse and DoS attacks
- **Headers**: Returns rate limit info in response headers

### Authentication Rate Limiting
- **Limit**: 5 login attempts per 15 minutes per IP
- **Purpose**: Prevents brute-force attacks
- **Skip Successful**: Successful logins don't count toward limit

### Account Lockout
- **Threshold**: 5 failed login attempts
- **Duration**: 30 minutes lockout
- **Reset**: Automatically resets on successful login
- **Why**: Protects against brute-force attacks on specific accounts

### CAPTCHA Support
- **Integration**: Ready for CAPTCHA service integration
- **When**: Can be enabled for repeated failures
- **Services**: Google reCAPTCHA, hCaptcha, etc.

## 7. Secure API Design

### HTTP Methods
- **GET**: Fetching data (idempotent, no side effects)
- **POST**: Creating data
- **PUT/PATCH**: Updating data
- **DELETE**: Removing data

### API Versioning
- **Current**: `/api/v1/`
- **Why**: Allows breaking changes without breaking existing clients
- **Migration**: Legacy routes redirect to v1

### HTTP Status Codes
- **200**: Success
- **201**: Created
- **400**: Bad Request (validation errors)
- **401**: Unauthorized (authentication required)
- **403**: Forbidden (authorization failed)
- **404**: Not Found
- **429**: Too Many Requests (rate limit)
- **500**: Internal Server Error

### Response Data
- **Minimal**: Only return necessary data
- **No Sensitive Info**: Never return passwords, tokens, or internal IDs
- **Consistent**: Standardized response format

## 8. Response and Header Security

### Security Headers
- **Content-Security-Policy**: Prevents XSS attacks
- **Strict-Transport-Security**: Forces HTTPS
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-Frame-Options**: Prevents clickjacking (DENY)
- **X-XSS-Protection**: Additional XSS protection
- **Referrer-Policy**: Controls referrer information

### CORS Configuration
- **Strict Origins**: Only allowed origins can make requests
- **Credentials**: Supports cookies and authentication
- **Methods**: Only allowed HTTP methods
- **Headers**: Only allowed headers
- **Why**: Prevents unauthorized cross-origin requests

### Token Security
- **Never in Response**: Tokens not returned in API responses (use cookies)
- **HttpOnly**: Cookies can't be accessed via JavaScript
- **Secure**: Cookies only sent over HTTPS in production
- **SameSite**: Prevents CSRF attacks

## 9. File Upload Security

### File Type Validation
- **MIME Type Check**: Validates Content-Type header
- **Extension Check**: Validates file extension
- **Magic Number**: Validates file content matches declared type
- **Why**: Prevents malicious file uploads

### File Size Limits
- **Maximum**: 5MB per file
- **Configurable**: Via environment variable
- **Why**: Prevents DoS attacks via large file uploads

### Storage Security
- **Outside Web Root**: Files stored outside public directory
- **Random Filenames**: Prevents directory traversal and guessing
- **Why**: Even if upload directory is exposed, files can't be executed

### Malware Scanning
- **Placeholder**: Ready for integration with antivirus service
- **Recommendation**: ClamAV, VirusTotal API, or commercial solution
- **Why**: Prevents malicious files from being stored

## Setup Instructions

### 1. Generate RSA Keys
```bash
node scripts/generateKeys.js
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Start Server
```bash
npm run dev  # Development
npm start    # Production
```

## Security Checklist

- [x] RS256 JWT signing
- [x] Token verification on every request
- [x] Refresh token rotation
- [x] Secure cookie storage
- [x] Input validation (Joi)
- [x] XSS protection
- [x] MongoDB injection protection
- [x] Security headers (CSP, HSTS, etc.)
- [x] CORS configuration
- [x] Rate limiting
- [x] Account lockout
- [x] Secure error handling
- [x] Security event logging
- [x] File upload validation
- [x] HTTPS enforcement
- [x] API versioning

## Production Deployment

1. **Generate Production Keys**: Use `generateKeys.js` on secure server
2. **Set Environment Variables**: Configure all production values
3. **Enable HTTPS**: Use reverse proxy (nginx, Apache) with SSL certificate
4. **Database Security**: Use encrypted connections and strong credentials
5. **Monitoring**: Set up alerts for security events
6. **Backup**: Regular backups of database (encrypted)
7. **Updates**: Keep dependencies updated for security patches

## Additional Recommendations

- Implement 2FA (Two-Factor Authentication)
- Add session management for additional security
- Implement API key management for third-party integrations
- Set up WAF (Web Application Firewall)
- Regular security audits and penetration testing
- Implement data encryption at rest for sensitive fields
- Add request signing for critical operations

