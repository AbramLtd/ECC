const crypto = require('crypto');
const hash = require('./hash');
const hmac = require('./hmac');
const getPublic = require('./getPublic');
const aes256Cbc = require('./aes256Cbc');
const derive = require('./derive');

async function encrypt(publicKeyTo, msg, opts) {
  opts = opts || {}; // eslint-disable-line no-param-reassign
  const ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
  const ephemPublicKey = getPublic(ephemPrivateKey);
  const Px = await derive(ephemPrivateKey, publicKeyTo);
  const PxHash = hash(Px);
  const iv = opts.iv || crypto.randomBytes(16);
  const encryptionKey = PxHash.slice(0, 32);
  const macKey = PxHash.slice(32);
  const ciphertext = aes256Cbc.encrypt(iv, encryptionKey, msg);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = hmac(macKey, dataToMac);
  return {
    iv,
    ephemPublicKey,
    ciphertext,
    mac,
  };
}

module.exports = encrypt;
