const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ["user", "manager", "admin"],
        default: "user"
    },
    refreshToken: { type: String, default: null },   // 🔥 store refresh token
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date, default: null },
    lastLogin: { type: Date, default: null },
    isActive: { type: Boolean, default: true }

}, { timestamps: true });

// Index for performance
userSchema.index({ email: 1 });
userSchema.index({ refreshToken: 1 });

module.exports = mongoose.model("User", userSchema);
