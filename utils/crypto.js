const crypto = require('crypto');

function generateSecureToken(size = 32) {
  return crypto.randomBytes(size).toString('hex');
}

async function hashPassword(password) {
  const salt = await crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

module.exports = { generateSecureToken, hashPassword };
