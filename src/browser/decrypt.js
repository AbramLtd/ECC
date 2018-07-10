const derive = require('./derive');
const getPublic = require('./getPublic');
const hash = require('./hash');
const { verify } = require('./hmac');
const aes256Cbc = require('./aes256Cbc');
const assert = require('assert');

const cryptoObj = crypto || msCrypto || {};
var subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function decrypt(privateKey, opts) {
  assert(subtle, "WebCryptoAPI is not available");
  const px = derive(privateKey, opts.ephemPublicKey);
  const sha512 = await hash(px);
  const encryptionKey = sha512.slice(0,32);
  var macKey = sha512.slice(32);
  var dataToMac = Buffer.concat([
    opts.iv,
    opts.ephemPublicKey,
    opts.ciphertext
  ]);
  console.log('mac', macKey, dataToMac, opts.mac);
  assert(await verify(macKey, dataToMac, opts.mac), 'Malformed MAC');
  const msg = await aes256Cbc.decrypt(opts.iv, encryptionKey, opts.ciphertext);
  return new Buffer(new Uint8Array(msg));
}

module.exports = decrypt;
