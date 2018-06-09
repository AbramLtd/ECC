const crypto = require('crypto');

function aes256CbcEncrypt(iv, key, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

module.exports = aes256CbcEncrypt;
