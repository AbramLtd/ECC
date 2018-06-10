const { Buffer } = require('buffer/');

const cryptoObj = crypto || msCrypto || {};
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function hash(msg) {
  const result = subtle.digest({ name: 'SHA-512' }, msg);
  return Buffer.from(new Uint8Array(result));
}

module.exports = hash;
