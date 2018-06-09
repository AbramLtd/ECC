const crypto = require('crypto');

function hmac(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest();
}

module.exports = hmac;
