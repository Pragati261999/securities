# Postman Testing Guide - Security Features

This guide shows you how to test all security features using Postman.

## Setup

### 1. Start the Server
```bash
cd backend
npm run dev
```

### 2. Import Postman Collection
Create a new Postman collection or use the examples below.

### 3. Set Base URL
Create an environment variable:
- Variable: `baseUrl`
- Value: `http://localhost:5000`

---

## Test 1: Authentication & Authorization

### 1.1 Register a User
**Request:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "Test User",
  "email": "test@example.com",
  "password": "SecurePass123!",
  "role": "user"
}
```

**Expected Response (201):**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "...",
    "name": "Test User",
    "email": "test@example.com",
    "role": "user"
  }
}
```

**Test Points:**
- ✅ Password is hashed (not returned in response)
- ✅ Role defaults to "user" if not specified
- ✅ Email validation works

### 1.2 Login
**Request:**
```
POST {{baseUrl}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response (200):**
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Save Token:**
- Copy `accessToken` to a Postman variable: `accessToken`
- Copy `refreshToken` to a Postman variable: `refreshToken`

**Test Points:**
- ✅ RS256 JWT tokens generated
- ✅ Tokens have proper structure (3 parts separated by dots)
- ✅ Access token expires in 15 minutes
- ✅ Refresh token expires in 7 days

### 1.3 Access Protected Route (Valid Token)
**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
Authorization: Bearer {{accessToken}}
```

**Expected Response (200):**
```json
{
  "message": "User profile accessible",
  "user": {
    "id": "...",
    "role": "user"
  }
}
```

**Test Points:**
- ✅ Token verification works
- ✅ User data retrieved from database (not just JWT)
- ✅ Role-based access control works

### 1.4 Access Protected Route (Invalid Token)
**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
Authorization: Bearer invalid_token_here
```

**Expected Response (401):**
```json
{
  "message": "Invalid or expired token"
}
```

**Test Points:**
- ✅ Invalid tokens are rejected
- ✅ Generic error message (no stack trace)

### 1.5 Access Protected Route (Expired Token)
**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
Authorization: Bearer <expired_token>
```

**Expected Response (401):**
```json
{
  "message": "Invalid or expired token"
}
```

**To Test:**
1. Wait 15+ minutes after login
2. Try using the access token
3. Should get 401 error

**Test Points:**
- ✅ Expired tokens are rejected
- ✅ Token expiration works correctly

### 1.6 Access Admin Route (Unauthorized)
**Request:**
```
GET {{baseUrl}}/api/v1/user/admin
Authorization: Bearer {{accessToken}}
```

**Expected Response (403):**
```json
{
  "message": "Access denied: insufficient permissions"
}
```

**Test Points:**
- ✅ RBAC works correctly
- ✅ Regular users can't access admin routes

### 1.7 Access Admin Route (Authorized)
**First, register an admin:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "Admin User",
  "email": "admin@example.com",
  "password": "AdminPass123!",
  "role": "admin"
}
```

**Then login and use admin token:**
```
GET {{baseUrl}}/api/v1/user/admin
Authorization: Bearer {{adminAccessToken}}
```

**Expected Response (200):**
```json
{
  "message": "Admin dashboard"
}
```

**Test Points:**
- ✅ Admin role has access
- ✅ RBAC correctly allows authorized users

---

## Test 2: Token Management

### 2.1 Refresh Token
**Request:**
```
POST {{baseUrl}}/api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{{refreshToken}}"
}
```

**Expected Response (200):**
```json
{
  "accessToken": "new_access_token...",
  "refreshToken": "new_refresh_token..."
}
```

**Important:** Save the new tokens!

**Test Points:**
- ✅ New tokens generated
- ✅ Old refresh token invalidated (try using it again - should fail)
- ✅ Token rotation works

### 2.2 Use Old Refresh Token (Should Fail)
**Request:**
```
POST {{baseUrl}}/api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<old_refresh_token_from_previous_request>"
}
```

**Expected Response (403):**
```json
{
  "message": "Invalid refresh token"
}
```

**Test Points:**
- ✅ Old refresh token is invalidated
- ✅ Token rotation prevents replay attacks

### 2.3 Logout
**Request:**
```
POST {{baseUrl}}/api/v1/auth/logout
Content-Type: application/json

{
  "refreshToken": "{{refreshToken}}"
}
```

**Expected Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

**Test Points:**
- ✅ Token revoked immediately
- ✅ Can't use refresh token after logout

### 2.4 Try Refresh After Logout (Should Fail)
**Request:**
```
POST {{baseUrl}}/api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{{refreshToken}}"
}
```

**Expected Response (403):**
```json
{
  "message": "Invalid refresh token"
}
```

**Test Points:**
- ✅ Token revocation works
- ✅ Logged out tokens can't be used

---

## Test 3: Input Validation

### 3.1 Invalid Email Format
**Request:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "Test",
  "email": "invalid-email",
  "password": "SecurePass123!"
}
```

**Expected Response (400):**
```json
{
  "message": "Validation error",
  "errors": [
    {
      "field": "email",
      "message": "\"email\" must be a valid email"
    }
  ]
}
```

**Test Points:**
- ✅ Email validation works
- ✅ Clear error messages
- ✅ Input sanitization

### 3.2 Weak Password
**Request:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "Test",
  "email": "test2@example.com",
  "password": "weak"
}
```

**Expected Response (400):**
```json
{
  "message": "Validation error",
  "errors": [
    {
      "field": "password",
      "message": "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    }
  ]
}
```

**Test Points:**
- ✅ Password strength validation
- ✅ Specific error messages

### 3.3 SQL Injection Attempt
**Request:**
```
POST {{baseUrl}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "admin@example.com' OR '1'='1",
  "password": "anything"
}
```

**Expected Response (400 or 401):**
```json
{
  "message": "Validation error"
}
```

**Test Points:**
- ✅ SQL injection prevented
- ✅ Input sanitized
- ✅ MongoDB injection protection works

### 3.4 XSS Attempt
**Request:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "<script>alert('XSS')</script>",
  "email": "xss@example.com",
  "password": "SecurePass123!"
}
```

**Check Response:** Name should be sanitized (script tags removed/escaped)

**Test Points:**
- ✅ XSS protection works
- ✅ Malicious scripts sanitized

---

## Test 4: Rate Limiting

### 4.1 Test General Rate Limiting
**Create a Collection Runner:**
1. Create a request: `GET {{baseUrl}}/api/v1/user/public`
2. Duplicate it 101 times
3. Run collection
4. After 100 requests, should get 429 error

**Request:**
```
GET {{baseUrl}}/api/v1/user/public
```

**Expected Response (429) after 100 requests:**
```json
{
  "message": "Too many requests from this IP, please try again later."
}
```

**Test Points:**
- ✅ Rate limiting works (100 req/15min)
- ✅ Proper 429 status code
- ✅ Rate limit headers in response

### 4.2 Test Auth Rate Limiting
**Request (run 6 times quickly):**
```
POST {{baseUrl}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "wrongpassword"
}
```

**Expected Response (429) after 5 attempts:**
```json
{
  "message": "Too many login attempts, please try again later."
}
```

**Test Points:**
- ✅ Auth rate limiting stricter (5 req/15min)
- ✅ Prevents brute force attacks

### 4.3 Test Account Lockout
**Request (run 6 times with wrong password):**
```
POST {{baseUrl}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "wrongpassword"
}
```

**Expected Response (423) after 5 failures:**
```json
{
  "message": "Account locked due to multiple failed login attempts. Please try again in 30 minute(s)."
}
```

**Test Points:**
- ✅ Account lockout after 5 failures
- ✅ 30-minute lockout period
- ✅ Prevents targeted brute force

### 4.4 Test Account Unlock After Successful Login
**After lockout, login with correct password:**
```
POST {{baseUrl}}/api/v1/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response (200):**
```json
{
  "message": "Login successful",
  "accessToken": "...",
  "refreshToken": "..."
}
```

**Then try wrong password again - should reset lockout counter**

**Test Points:**
- ✅ Successful login resets lockout
- ✅ Account unlocked automatically

---

## Test 5: Error Handling

### 5.1 Test Generic Error Messages
**Request with invalid endpoint:**
```
GET {{baseUrl}}/api/v1/nonexistent
```

**Expected Response (404):**
```json
{
  "message": "Route /api/v1/nonexistent not found"
}
```

**Test Points:**
- ✅ No stack traces in response
- ✅ Generic error messages
- ✅ No sensitive information leaked

### 5.2 Test Database Error Handling
**Try to register duplicate email:**
```
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

{
  "name": "Test",
  "email": "test@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response (400):**
```json
{
  "message": "Email already registered"
}
```

**Test Points:**
- ✅ No database error details exposed
- ✅ User-friendly error message

---

## Test 6: Security Headers

### 6.1 Check Security Headers
**Request:**
```
GET {{baseUrl}}/
```

**Check Response Headers:**
- `Content-Security-Policy` - Should be present
- `Strict-Transport-Security` - Should be present
- `X-Content-Type-Options` - Should be `nosniff`
- `X-Frame-Options` - Should be `DENY`
- `X-XSS-Protection` - Should be present

**In Postman:**
1. Send request
2. Click "Headers" tab in response
3. Check for security headers

**Test Points:**
- ✅ All security headers present
- ✅ Proper values configured

### 6.2 Test CORS
**Request with Origin header:**
```
GET {{baseUrl}}/api/v1/user/public
Origin: http://localhost:3000
```

**Check Response Headers:**
- `Access-Control-Allow-Origin` - Should be `http://localhost:3000`
- `Access-Control-Allow-Credentials` - Should be `true`

**Test with unauthorized origin:**
```
GET {{baseUrl}}/api/v1/user/public
Origin: http://malicious-site.com
```

**Expected:** CORS error or no CORS headers

**Test Points:**
- ✅ CORS only allows configured origins
- ✅ Credentials allowed for authorized origins

---

## Test 7: File Upload Security

### 7.1 Upload Valid File
**Request:**
```
POST {{baseUrl}}/api/v1/upload/upload
Authorization: Bearer {{accessToken}}
Content-Type: multipart/form-data

file: [Select a valid image file (JPEG, PNG, or GIF)]
```

**Expected Response (201):**
```json
{
  "message": "File uploaded successfully",
  "file": {
    "id": "random_filename.jpg",
    "originalName": "test.jpg",
    "size": 12345,
    "mimetype": "image/jpeg",
    "uploadedAt": "2024-01-01T00:00:00.000Z"
  }
}
```

**Test Points:**
- ✅ File uploaded successfully
- ✅ Random filename generated
- ✅ File stored outside web root

### 7.2 Upload Invalid File Type
**Request:**
```
POST {{baseUrl}}/api/v1/upload/upload
Authorization: Bearer {{accessToken}}
Content-Type: multipart/form-data

file: [Select an .exe or .bat file]
```

**Expected Response (400):**
```json
{
  "message": "Invalid file type. Allowed types: image/jpeg, image/png, image/gif, application/pdf, text/plain, application/msword, application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}
```

**Test Points:**
- ✅ File type validation works
- ✅ Dangerous file types rejected

### 7.3 Upload Oversized File
**Request:**
```
POST {{baseUrl}}/api/v1/upload/upload
Authorization: Bearer {{accessToken}}
Content-Type: multipart/form-data

file: [Select a file larger than 5MB]
```

**Expected Response (400):**
```json
{
  "message": "File too large"
}
```

**Test Points:**
- ✅ File size limit enforced
- ✅ Prevents DoS via large files

### 7.4 Upload Without Authentication
**Request:**
```
POST {{baseUrl}}/api/v1/upload/upload
Content-Type: multipart/form-data

file: [Select a file]
```

**Expected Response (401):**
```json
{
  "message": "No token provided"
}
```

**Test Points:**
- ✅ Authentication required
- ✅ Unauthorized access prevented

---

## Test 8: API Versioning

### 8.1 Test Versioned Endpoint
**Request:**
```
GET {{baseUrl}}/api/v1/user/public
```

**Expected Response (200):**
```json
{
  "message": "Public route: no token needed"
}
```

**Test Points:**
- ✅ Versioned API works
- ✅ `/api/v1/` prefix required

### 8.2 Test Legacy Endpoint (Still Works)
**Request:**
```
GET {{baseUrl}}/api/user/public
```

**Expected Response (200):**
```json
{
  "message": "Public route: no token needed"
}
```

**Test Points:**
- ✅ Legacy routes still work
- ✅ Backward compatibility maintained

---

## Test 9: Token in Different Formats

### 9.1 Token in Authorization Header
**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
Authorization: Bearer {{accessToken}}
```

**Expected Response (200):**
```json
{
  "message": "User profile accessible",
  "user": { ... }
}
```

**Test Points:**
- ✅ Bearer token format works
- ✅ Standard OAuth 2.0 format

### 9.2 Token in Cookie (If Using Browser)
**Note:** Postman can simulate cookies

**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
Cookie: accessToken={{accessToken}}
```

**Expected Response (200):**
```json
{
  "message": "User profile accessible",
  "user": { ... }
}
```

**Test Points:**
- ✅ Cookie-based authentication works
- ✅ HttpOnly cookies supported

### 9.3 Token in Custom Header
**Request:**
```
GET {{baseUrl}}/api/v1/user/profile
X-Access-Token: {{accessToken}}
```

**Expected Response (200):**
```json
{
  "message": "User profile accessible",
  "user": { ... }
}
```

**Test Points:**
- ✅ Custom header format works
- ✅ Multiple token formats supported

---

## Postman Collection JSON

Save this as a Postman collection:

```json
{
  "info": {
    "name": "Secure Task Manager API Tests",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:5000"
    },
    {
      "key": "accessToken",
      "value": ""
    },
    {
      "key": "refreshToken",
      "value": ""
    }
  ],
  "item": [
    {
      "name": "Authentication",
      "item": [
        {
          "name": "Register User",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"name\": \"Test User\",\n  \"email\": \"test@example.com\",\n  \"password\": \"SecurePass123!\",\n  \"role\": \"user\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/register",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "register"]
            }
          }
        },
        {
          "name": "Login",
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "if (pm.response.code === 200) {",
                  "    var jsonData = pm.response.json();",
                  "    pm.environment.set('accessToken', jsonData.accessToken);",
                  "    pm.environment.set('refreshToken', jsonData.refreshToken);",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"SecurePass123!\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/login",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "login"]
            }
          }
        },
        {
          "name": "Get Profile",
          "request": {
            "method": "GET",
            "header": [
              {
                "key": "Authorization",
                "value": "Bearer {{accessToken}}"
              }
            ],
            "url": {
              "raw": "{{baseUrl}}/api/v1/user/profile",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "user", "profile"]
            }
          }
        },
        {
          "name": "Refresh Token",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refreshToken\": \"{{refreshToken}}\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/refresh",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "refresh"]
            }
          }
        },
        {
          "name": "Logout",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refreshToken\": \"{{refreshToken}}\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/logout",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "logout"]
            }
          }
        }
      ]
    },
    {
      "name": "Rate Limiting",
      "item": [
        {
          "name": "Public Route (Rate Limit Test)",
          "request": {
            "method": "GET",
            "url": {
              "raw": "{{baseUrl}}/api/v1/user/public",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "user", "public"]
            }
          }
        }
      ]
    },
    {
      "name": "Validation",
      "item": [
        {
          "name": "Invalid Email",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"name\": \"Test\",\n  \"email\": \"invalid-email\",\n  \"password\": \"SecurePass123!\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/register",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "register"]
            }
          }
        },
        {
          "name": "Weak Password",
          "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"name\": \"Test\",\n  \"email\": \"test2@example.com\",\n  \"password\": \"weak\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/api/v1/auth/register",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "auth", "register"]
            }
          }
        }
      ]
    },
    {
      "name": "Authorization",
      "item": [
        {
          "name": "Admin Route (Unauthorized)",
          "request": {
            "method": "GET",
            "header": [
              {
                "key": "Authorization",
                "value": "Bearer {{accessToken}}"
              }
            ],
            "url": {
              "raw": "{{baseUrl}}/api/v1/user/admin",
              "host": ["{{baseUrl}}"],
              "path": ["api", "v1", "user", "admin"]
            }
          }
        }
      ]
    }
  ]
}
```

---

## Testing Checklist

Use this checklist to verify all security features:

### Authentication & Authorization
- [ ] Register user with valid data
- [ ] Login and receive tokens
- [ ] Access protected route with valid token
- [ ] Access protected route with invalid token (401)
- [ ] Access protected route with expired token (401)
- [ ] Access admin route as regular user (403)
- [ ] Access admin route as admin (200)

### Token Management
- [ ] Refresh token generates new tokens
- [ ] Old refresh token invalidated after refresh
- [ ] Logout revokes token
- [ ] Can't use token after logout

### Input Validation
- [ ] Invalid email format rejected
- [ ] Weak password rejected
- [ ] SQL injection attempt blocked
- [ ] XSS attempt sanitized

### Rate Limiting
- [ ] General rate limit (100 req/15min)
- [ ] Auth rate limit (5 req/15min)
- [ ] Account lockout after 5 failures
- [ ] Account unlock after successful login

### Error Handling
- [ ] Generic error messages (no stack traces)
- [ ] No sensitive information in errors
- [ ] Proper HTTP status codes

### Security Headers
- [ ] Content-Security-Policy present
- [ ] Strict-Transport-Security present
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] CORS configured correctly

### File Upload
- [ ] Valid file uploads successfully
- [ ] Invalid file type rejected
- [ ] Oversized file rejected
- [ ] Authentication required for upload

### API Design
- [ ] Versioned endpoints work
- [ ] Proper HTTP methods used
- [ ] Consistent status codes

---

## Tips for Testing

1. **Use Postman Environments**: Create separate environments for dev/staging/prod
2. **Automate Token Refresh**: Use Postman scripts to auto-refresh tokens
3. **Collection Runner**: Use collection runner to test rate limiting
4. **Pre-request Scripts**: Automate token injection in headers
5. **Tests Tab**: Add assertions to verify responses

## Example Postman Pre-request Script

```javascript
// Auto-refresh token if expired
const tokenExpiry = pm.environment.get("tokenExpiry");
if (!tokenExpiry || new Date() > new Date(tokenExpiry)) {
    pm.sendRequest({
        url: pm.environment.get("baseUrl") + "/api/v1/auth/refresh",
        method: 'POST',
        header: {
            'Content-Type': 'application/json'
        },
        body: {
            mode: 'raw',
            raw: JSON.stringify({
                refreshToken: pm.environment.get("refreshToken")
            })
        }
    }, function (err, res) {
        if (res.code === 200) {
            const jsonData = res.json();
            pm.environment.set("accessToken", jsonData.accessToken);
            pm.environment.set("refreshToken", jsonData.refreshToken);
            pm.environment.set("tokenExpiry", new Date(Date.now() + 14 * 60 * 1000));
        }
    });
}
```

This guide covers all security features. Test each section systematically to verify everything works correctly!

