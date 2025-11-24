/**
 * RSA Key Pair Generation Script
 * Generates secure RSA-256 keys for JWT signing
 * 
 * Run: node scripts/generateKeys.js
 */

const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');

const keysDir = path.join(__dirname, '../keys');

// Ensure keys directory exists
fs.ensureDirSync(keysDir);

// Generate RSA key pair (2048 bits minimum for RS256)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048, // 2048 bits minimum for production
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Write keys to files
const privateKeyPath = path.join(keysDir, 'private.pem');
const publicKeyPath = path.join(keysDir, 'public.pem');

fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 }); // Read/write for owner only
fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 }); // Readable by all

console.log('✅ RSA key pair generated successfully!');
console.log(`Private key: ${privateKeyPath}`);
console.log(`Public key: ${publicKeyPath}`);
console.log('\n⚠️  IMPORTANT: Keep the private key secure and never commit it to version control!');
console.log('⚠️  Add keys/private.pem to .gitignore');

