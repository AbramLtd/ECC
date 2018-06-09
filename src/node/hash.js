const crypto = require('crypto');

function hash(msg) {
  return crypto.createHash('sha512').update(msg).digest();
}

module.exports = hash;
