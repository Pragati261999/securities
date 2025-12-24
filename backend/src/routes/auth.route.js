// const express = require("express");
// const router = express.Router();
// const { register, login, refresh, logout } = require("../controllers/auth.controller");
// const auth = require("../middleware/auth.middleware");
// const { validate, schemas } = require("../middleware/validation.middleware");
// const { accountLockout, verifyCaptcha } = require("../middleware/rateLimiter.middleware");
// const { asyncHandler } = require("../middleware/errorHandler.middleware");

// // Public routes with validation and rate limiting
// router.post("/register", 
//   validate(schemas.register),
//   asyncHandler(register)
// );

// router.post("/login", 
//   validate(schemas.login),
//   accountLockout,
//   verifyCaptcha, // Add CAPTCHA for production
//   asyncHandler(login)
// );

// // Token refresh with validation
// router.post("/refresh", 
//   validate(schemas.refreshToken),
//   asyncHandler(refresh)
// );

// // Logout
// router.post("/logout", asyncHandler(logout));

// // Protected routes
// router.get("/profile", auth, (req, res) => {
//     res.json({ 
//       message: "Access granted", 
//       user: {
//         id: req.user.id,
//         role: req.user.role
//       }
//     });
// });

// module.exports = router;



const express = require("express");
const router = express.Router();

const { register, login, refresh, logout } = require("../controllers/auth.controller");
const auth = require("../middleware/auth.middleware");
const { validate, schemas } = require("../middleware/validation.middleware");
const { accountLockout, verifyCaptcha } = require("../middleware/rateLimiter.middleware");
const { asyncHandler } = require("../middleware/errorHandler.middleware");

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication and Authorization APIs
 */

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *                 example: Pragati Tiwari
 *               email:
 *                 type: string
 *                 example: pragati@example.com
 *               password:
 *                 type: string
 *                 example: Password@123
 *               role:
 *                 type: string
 *                 enum: [user, manager, admin]
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 */
router.post(
  "/register",
  validate(schemas.register),
  asyncHandler(register)
);

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: pragati@example.com
 *               password:
 *                 type: string
 *                 example: Password@123
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Too many login attempts
 */
router.post(
  "/login",
  validate(schemas.login),
  accountLockout,
  verifyCaptcha,
  asyncHandler(login)
);

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *     responses:
 *       200:
 *         description: Token refreshed
 *       401:
 *         description: Invalid refresh token
 */
router.post(
  "/refresh",
  validate(schemas.refreshToken),
  asyncHandler(refresh)
);

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post(
  "/logout",
  auth,
  asyncHandler(logout)
);

// /**
//  * @swagger
//  * /api/v1/auth/profile:
//  *   get:
//  *     summary: Get logged-in user profile
//  *     tags: [Auth]
//  *     security:
//  *       - BearerAuth: []
//  *     responses:
//  *       200:
//  *         description: Profile data returned
//  *       401:
//  *         description: Unauthorized
//  */
// router.get(
//   "/profile",
//   auth,
//   (req, res) => {
//     res.json({
//       message: "Access granted",
//       user: {
//         id: req.user.id,
//         role: req.user.role,
//       },
//     });
//   }
// );


/**
 * @swagger
 * /api/v1/user/profile:
 *   get:
 *     summary: Get logged-in user profile
 *     tags: [User]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Profile fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *                     role:
 *                       type: string
 *                     isActive:
 *                       type: boolean
 *                     lastLogin:
 *                       type: string
 *                       format: date-time
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */
router.get('/profile', auth, getProfile);


module.exports = router;
