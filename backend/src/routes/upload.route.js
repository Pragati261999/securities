/**
 * File Upload Routes
 * Demonstrates secure file upload implementation
 */

const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth.middleware");
const authorize = require("../middleware/role.middleware");
const { upload, validateFileContent, cleanupFile } = require("../middleware/fileUpload.middleware");
const { asyncHandler } = require("../middleware/errorHandler.middleware");
const logger = require("../config/logger");

// Upload file (authenticated users only)
router.post(
  "/upload",
  auth,
  upload.single("file"),
  validateFileContent,
  cleanupFile,
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        message: "No file uploaded",
      });
    }

    logger.info("File uploaded successfully", {
      userId: req.user.id,
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
    });

    res.status(201).json({
      message: "File uploaded successfully",
      file: {
        id: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        uploadedAt: new Date(),
      },
    });
  })
);

// Get uploaded file info (admin only)
router.get(
  "/files",
  auth,
  authorize("admin", "manager"),
  asyncHandler(async (req, res) => {
    // In a real application, you would query a database for file metadata
    // For security, never return file paths or allow direct file access
    res.json({
      message: "File list endpoint - implement file metadata storage",
    });
  })
);

module.exports = router;

