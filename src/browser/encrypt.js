const derive = require('./derive');
const getPublic = require('./getPublic');
const hash = require('./hash');
const { sign } = require('./hmac');
const aes256Cbc = require('./aes256Cbc');
const assert = require('assert');

const cryptoObj = crypto || msCrypto || {};
var subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

function randomBytes(size) {
  const arr = new Uint8Array(size);
  cryptoObj.getRandomValues(arr);
  return Buffer.from(arr);
}

async function encrypt(publicKeyTo, msg, opts) {
  assert(subtle, "WebCryptoAPI is not available");
  opts = opts || {};
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  ephemPublicKey = getPublic(ephemPrivateKey);
  const px = derive(ephemPrivateKey, publicKeyTo);
  const sha512 = await hash(px);
  const iv = opts.iv || randomBytes(16);
  const encryptionKey = sha512.slice(0, 32);
  const macKey = sha512.slice(32);
  const ciphertext = await aes256Cbc.encrypt(iv, encryptionKey, msg);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await sign(macKey, dataToMac);
  return {
    iv: iv,
    ephemPublicKey: ephemPublicKey,
    ciphertext: ciphertext,
    mac: mac,
  };
};

module.exports = encrypt;