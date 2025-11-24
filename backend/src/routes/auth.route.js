const express = require("express");
const router = express.Router();
const { register, login, refresh, logout } = require("../controllers/auth.controller");
const auth = require("../middleware/auth.middleware");
const { validate, schemas } = require("../middleware/validation.middleware");
const { accountLockout, verifyCaptcha } = require("../middleware/rateLimiter.middleware");
const { asyncHandler } = require("../middleware/errorHandler.middleware");

// Public routes with validation and rate limiting
router.post("/register", 
  validate(schemas.register),
  asyncHandler(register)
);

router.post("/login", 
  validate(schemas.login),
  accountLockout,
  verifyCaptcha, // Add CAPTCHA for production
  asyncHandler(login)
);

// Token refresh with validation
router.post("/refresh", 
  validate(schemas.refreshToken),
  asyncHandler(refresh)
);

// Logout
router.post("/logout", asyncHandler(logout));

// Protected routes
router.get("/profile", auth, (req, res) => {
    res.json({ 
      message: "Access granted", 
      user: {
        id: req.user.id,
        role: req.user.role
      }
    });
});

module.exports = router;
