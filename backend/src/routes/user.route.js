const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth.middleware");
const authorize = require("../middleware/role.middleware");

// PUBLIC ROUTE
router.get("/public", (req, res) => {
    res.send("Public route: no token needed");
});

console.log("authorize:",authorize);

// PROTECTED ROUTE (user OR admin)
router.get("/profile", auth, authorize("user", "admin"), (req, res) => {
    res.json({ message: "User profile accessible", user: req.user });
});

// ADMIN ONLY ROUTE
router.get("/admin", auth, authorize("admin"), (req, res) => {
    res.json({ message: "Admin dashboard" });
});

// SUPERADMIN ONLY ROUTE
router.get("/super", auth, authorize("superadmin"), (req, res) => {
    res.json({ message: "Super admin access" });
});

module.exports = router;
