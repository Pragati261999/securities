# Quick Start Guide - Secure Task Manager

## Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or cloud instance)
- npm or yarn

## Setup Steps

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Generate RSA Keys
```bash
node scripts/generateKeys.js
```

This creates:
- `keys/private.pem` - Private key for signing JWTs (KEEP SECRET!)
- `keys/public.pem` - Public key for verifying JWTs

**⚠️ IMPORTANT**: Never commit `private.pem` to version control!

### 3. Configure Environment
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/secure-task-manager
ALLOWED_ORIGINS=http://localhost:3000
```

### 4. Start MongoDB
Make sure MongoDB is running on your system.

### 5. Start the Server
```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

Server will start on `http://localhost:5000`

## Testing the API

### 1. Register a User
```bash
curl -X POST http://localhost:5000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "role": "user"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

Response:
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Access Protected Route
```bash
curl -X GET http://localhost:5000/api/v1/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Refresh Token
```bash
curl -X POST http://localhost:5000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### 5. Logout
```bash
curl -X POST http://localhost:5000/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

## Security Features Implemented

✅ **Authentication**
- RS256 JWT signing (asymmetric encryption)
- Token verification on every request
- Backend verification (never trusts JWT alone)

✅ **Token Management**
- Short-lived access tokens (15 minutes)
- Refresh token rotation
- Secure cookie storage (HttpOnly, Secure, SameSite)

✅ **Input Validation**
- Joi schema validation
- XSS protection
- MongoDB injection protection
- HTTP parameter pollution protection

✅ **Security Headers**
- Content-Security-Policy
- Strict-Transport-Security (HSTS)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff

✅ **Rate Limiting**
- General API rate limiting (100 req/15min)
- Auth rate limiting (5 req/15min)
- Account lockout (5 failed attempts = 30min lockout)

✅ **Error Handling**
- Generic error messages (no information leakage)
- Security event logging
- Sensitive data filtering in logs

✅ **File Upload Security**
- File type validation (MIME, extension, magic numbers)
- Size limits (5MB)
- Storage outside web root
- Random filenames

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/refresh` - Refresh tokens
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/profile` - Get user profile (protected)

### Users
- `GET /api/v1/user/profile` - Get profile (protected)
- `GET /api/v1/user/admin` - Admin only (protected)

### File Upload
- `POST /api/v1/upload/upload` - Upload file (protected)
- `GET /api/v1/upload/files` - List files (admin/manager only)

## Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)

## Rate Limits

- **General API**: 100 requests per 15 minutes per IP
- **Authentication**: 5 requests per 15 minutes per IP
- **Account Lockout**: 5 failed login attempts = 30 minute lockout

## Troubleshooting

### "No token provided"
- Make sure you're sending the Authorization header: `Bearer YOUR_TOKEN`
- Or use cookies (if using browser)

### "Invalid or expired token"
- Token may have expired (15 minutes for access token)
- Use refresh token to get new access token

### "Account locked"
- Too many failed login attempts
- Wait 30 minutes or contact admin

### "Rate limit exceeded"
- Too many requests from your IP
- Wait 15 minutes before trying again

## Production Deployment

1. **Set NODE_ENV=production**
2. **Use HTTPS** (required for secure cookies)
3. **Configure CORS** with actual frontend domain
4. **Use environment variables** for all secrets
5. **Enable rate limiting** (already configured)
6. **Set up monitoring** for security events
7. **Regular backups** of database
8. **Keep dependencies updated**

## Next Steps

- Read `README_SECURITY.md` for detailed security documentation
- Read `SECURITY_EXPLANATION.md` for how each feature works
- Review code comments for implementation details
- Set up monitoring and alerting for production

