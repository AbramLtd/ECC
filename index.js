const crypto = require('crypto');

const secp256k1 = require('secp256k1');
const ecdh = require('./build/Release/ecdh'); // eslint-disable-line import/no-unresolved

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function sha512(msg) {
  return crypto.createHash('sha512').update(msg).digest();
}

function aes256CbcEncrypt(iv, key, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function hmacSha256(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest();
}

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

function pad32(msg) {
  let buf;
  if (msg.length < 32) {
    buf = Buffer.alloc(32);
    buf.fill(0);
    msg.copy(buf, 32 - msg.length);
    return buf;
  }
  return msg;
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer} A 65-byte public key.
 * @function
 */
function getPublic(privateKey) {
  assert(privateKey.length === 32, 'Bad private key');
  const compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

/**
 * Create an ECDSA signature.
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed
 * @return {Promise.<Buffer>} A promise that resolves with the
 * signature and rejects on bad key or message.
 */
function sign(privateKey, msg) {
  return new Promise(((resolve) => {
    assert(msg.length > 0, 'Message should not be empty');
    assert(msg.length <= 32, 'Message is too long');
    msg = pad32(msg); // eslint-disable-line no-param-reassign
    const sig = secp256k1.signSync(msg, privateKey).signature;
    resolve(secp256k1.signatureExport(sig));
  }));
}

/**
 * Verify an ECDSA signature.
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature
 * @return {Promise.<null>} A promise that resolves on correct signature
 * and rejects on bad key or signature.
 */
function verify(publicKey, msg, sig) {
  return new Promise(((resolve, reject) => {
    assert(msg.length > 0, 'Message should not be empty');
    assert(msg.length <= 32, 'Message is too long');
    msg = pad32(msg); // eslint-disable-line no-param-reassign
    sig = secp256k1.signatureImport(sig); // eslint-disable-line no-param-reassign
    if (secp256k1.verifySync(msg, sig, publicKey)) {
      resolve(null);
    } else {
      reject(new Error('Bad signature'));
    }
  }));
}

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived
 * shared secret (Px, 32 bytes) and rejects on bad key.
 */
function derive(privateKeyA, publicKeyB) {
  return new Promise(((resolve) => {
    resolve(ecdh.derive(privateKeyA, publicKeyB));
  }));
}

/**
 * Input/output structure for ECIES operations.
 * @typedef {Object} Ecies
 * @property {Buffer} iv - Initialization vector (16 bytes)
 * @property {Buffer} ephemPublicKey - Ephemeral public key (65 bytes)
 * @property {Buffer} ciphertext - The result of encryption (variable size)
 * @property {Buffer} mac - Message authentication code (32 bytes)
 */

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Ecies>} - A promise that resolves with the ECIES
 * structure on successful encryption and rejects on failure.
 */
function encrypt(publicKeyTo, msg, opts) {
  opts = opts || {}; // eslint-disable-line no-param-reassign
  let ephemPublicKey;
  return new Promise(((resolve) => {
    const ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  })).then((Px) => {
    const hash = sha512(Px);
    const iv = opts.iv || crypto.randomBytes(16);
    const encryptionKey = hash.slice(0, 32);
    const macKey = hash.slice(32);
    const ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
    const mac = hmacSha256(macKey, dataToMac);
    return {
      iv,
      ephemPublicKey,
      ciphertext,
      mac,
    };
  });
}

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} opts - ECIES structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with thederive
 * plaintext on successful decryption and rejects on failure.
 */
function decrypt(privateKey, opts) {
  derive(privateKey, opts.ephemPublicKey).then((Px) => {
    const hash = sha512(Px);
    const encryptionKey = hash.slice(0, 32);
    const macKey = hash.slice(32);
    const dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext,
    ]);
    const realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), 'Bad MAC');
    return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
}

module.exports = {
  decrypt,
  encrypt,
  derive,
  getPublic,
  verify,
  sign,
};