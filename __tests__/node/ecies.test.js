const getPublic = require('../../src/node/getPublic');
const encrypt = require('../../src/node/encrypt');
const decrypt = require('../../src/node/decrypt');

const ephemPrivateKey = Buffer.alloc(32);
ephemPrivateKey.fill(4);
const ephemPublicKey = getPublic(ephemPrivateKey);
const iv = Buffer.alloc(16);
iv.fill(5);
const ciphertext = Buffer.from('bbf3f0e7486b552b0e2ba9c4ca8c4579', 'hex');
const mac = Buffer.from('dbb14a9b53dbd6b763dba24dc99520f570cdf8095a8571db4bf501b535fda1ed', 'hex');
const encOpts = {
  ephemPrivateKey, iv,
};
const decOpts = {
  iv, ephemPublicKey, ciphertext, mac,
};


test('encrypt', () => {
  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const publicKeyB = getPublic(privateKeyB);
  const enc = encrypt(publicKeyB, Buffer.from('test'), encOpts);
  expect(enc.iv.equals(iv)).toBe(true);
});

test('decrypt', () => {
  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const msg = decrypt(privateKeyB, decOpts);
  expect(msg.toString()).toEqual('test');
});

test('encrypt and decrypt', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);

  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const enc = encrypt(publicKeyA, Buffer.from('secret'));
  const msg = decrypt(privateKeyA, enc);
  expect(msg.toString()).toEqual('secret');
});

test('Fail at bad private key when decrypting', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);

  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const enc = encrypt(publicKeyA, Buffer.from('test'));
  expect(() => {
    try {
      decrypt(privateKeyB, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Fail on bad IV when decrypting', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);
  const enc = encrypt(publicKeyA, Buffer.from('test'));
  enc.iv[0] ^= 1;
  expect(() => {
    try {
      decrypt(privateKeyA, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Fail on bad R when decrypting', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);
  const enc = encrypt(publicKeyA, Buffer.from('test'));
  enc.ephemPublicKey[0] ^= 1;
  expect(() => {
    try {
      decrypt(privateKeyA, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Fail on bad ciphertext when decrypting', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);
  const enc = encrypt(publicKeyA, Buffer.from('test'));
  enc.ciphertext[0] ^= 1;
  expect(() => {
    try {
      decrypt(privateKeyA, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Fail on bad MAC when decrypting', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);
  const enc = encrypt(publicKeyA, Buffer.from('test'));
  const origMac = enc.mac;
  enc.mac = mac.slice(1);
  expect(() => {
    try {
      decrypt(privateKeyA, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  enc.mac = origMac;
  enc.mac[10] ^= 1;
  expect(() => {
    try {
      decrypt(privateKeyA, enc);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});
