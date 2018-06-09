const derive = require('./derive');
const hash = require('./hash');
const hmac = require('./hmac');
const aes256Cbc = require('./aes256Cbc');
const assert = require('assert');

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i += 1) {
    res |= b1[i] ^ b2[i]; // eslint-disable-line no-bitwise
  }
  return res === 0;
}

function decrypt(privateKey, opts) {
  derive(privateKey, opts.ephemPublicKey).then((Px) => {
    const PxHash = hash(Px);
    const encryptionKey = PxHash.slice(0, 32);
    const macKey = PxHash.slice(32);
    const dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext,
    ]);
    const realMac = hmac(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), 'failed');
    return aes256Cbc.decrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
}

module.exports = decrypt;
