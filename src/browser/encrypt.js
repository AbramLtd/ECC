const { Buffer } = require('buffer/');
const derive = require('./derive');
const getPublic = require('./getPublic');
const hash = require('./hash');

const cryptoObj = crypto || msCrypto || {};

function randomBytes(size) {
  const arr = new Uint8Array(size);
  cryptoObj.getRandomValues(arr);
  return Buffer.from(arr);
}

async function encrypt(publicKeyTo, msg, opts) {
  opts = opts || {};
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  const ephemPublicKey = getPublic(ephemPrivateKey);
  const px = await derive(ephemPrivateKey, publicKeyTo);
  const pxHash = await hash(px);
  const iv = opts.iv || randomBytes(16);
  const encryptionKey = pxHash.slice(0, 32);
  const macKey = hash.slice(32);
  await aesCbcEncrypt(iv, encryptionKey, msg);
};

module.exports = encrypt;