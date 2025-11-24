/**
 * File Upload Security Middleware
 * Validates file type, size, and content before saving
 */

const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const crypto = require('crypto');

// Allowed file types (MIME types)
const ALLOWED_MIME_TYPES = {
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'application/pdf': ['.pdf'],
  'text/plain': ['.txt'],
  'application/msword': ['.doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
};

// Maximum file size (5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Storage configuration - store outside web root
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    // Store files outside web root directory
    const uploadDir = path.join(__dirname, '../../uploads');
    
    // Create directory if it doesn't exist
    await fs.ensureDir(uploadDir);
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure random filename to prevent directory traversal
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    
    // Validate extension
    const allowedExts = Object.values(ALLOWED_MIME_TYPES).flat();
    if (!allowedExts.includes(ext)) {
      return cb(new Error('Invalid file extension'));
    }
    
    cb(null, `${randomName}${ext}`);
  },
});

// File filter - validate file type
const fileFilter = (req, file, cb) => {
  // Check MIME type
  if (!ALLOWED_MIME_TYPES[file.mimetype]) {
    return cb(new Error('Invalid file type. Allowed types: ' + Object.keys(ALLOWED_MIME_TYPES).join(', ')));
  }

  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedExts = ALLOWED_MIME_TYPES[file.mimetype];
  
  if (!allowedExts.includes(ext)) {
    return cb(new Error(`File extension ${ext} does not match MIME type ${file.mimetype}`));
  }

  cb(null, true);
};

// Multer configuration
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1, // Limit to 1 file per request
  },
});

// Additional file validation middleware
const validateFileContent = async (req, res, next) => {
  if (!req.file) {
    return next();
  }

  try {
    const filePath = req.file.path;
    const fileBuffer = await fs.readFile(filePath);
    
    // Basic magic number validation (file signature)
    const magicNumbers = {
      'image/jpeg': [0xFF, 0xD8, 0xFF],
      'image/png': [0x89, 0x50, 0x4E, 0x47],
      'image/gif': [0x47, 0x49, 0x46, 0x38],
      'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
    };

    const expectedMagic = magicNumbers[req.file.mimetype];
    
    if (expectedMagic) {
      const matches = expectedMagic.every((byte, index) => fileBuffer[index] === byte);
      
      if (!matches) {
        // Delete the file
        await fs.remove(filePath);
        return res.status(400).json({
          message: 'File content does not match declared type',
        });
      }
    }

    // TODO: Integrate malware scanning service here
    // Example: await scanFileForMalware(filePath);

    next();
  } catch (error) {
    // Clean up file on error
    if (req.file && req.file.path) {
      await fs.remove(req.file.path).catch(() => {});
    }
    
    return res.status(500).json({
      message: 'Error validating file',
    });
  }
};

// Cleanup middleware - remove file if request fails
const cleanupFile = async (req, res, next) => {
  // Store original send function
  const originalSend = res.send;
  
  res.send = function (data) {
    // If response is an error, clean up file
    if (res.statusCode >= 400 && req.file && req.file.path) {
      fs.remove(req.file.path).catch(() => {});
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

module.exports = {
  upload,
  validateFileContent,
  cleanupFile,
  MAX_FILE_SIZE,
  ALLOWED_MIME_TYPES,
};

