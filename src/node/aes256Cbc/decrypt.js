const crypto = require('crypto');

function aes256CbcDecrypt(iv, key, ciphertext) {
  const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

module.exports = aes256CbcDecrypt;
