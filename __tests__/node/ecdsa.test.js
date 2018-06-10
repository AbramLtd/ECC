
const { createHash } = require('crypto');
const ECDSA = require('../../src/node/ECDSA');
const getPublic = require('../../src/node/getPublic');


test('Sign message', () => {
  const privateKey = Buffer.alloc(32);
  privateKey.fill(1);
  const msg = createHash('sha256').update('test').digest();
  const signature = ECDSA.sign(privateKey, msg);
  expect(Buffer.isBuffer(signature)).toBe(true);
  expect(signature.toString('hex')).toEqual('3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c');
});

test('Sign and verify message', () => {
  const privateKey = Buffer.alloc(32);
  privateKey.fill(1);
  const publicKey = getPublic(privateKey);
  const msg = createHash('sha256').update('test').digest();
  const signature = ECDSA.sign(privateKey, msg);
  expect(Buffer.isBuffer(signature)).toBe(true);
  expect(signature.toString('hex')).toEqual('3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c');
  expect(ECDSA.verify(publicKey, msg, signature)).toBe(true);
});

test('Sign and fail at verifing wrong message', () => {
  const privateKey = Buffer.alloc(32);
  privateKey.fill(1);
  const publicKey = getPublic(privateKey);
  const msg = createHash('sha256').update('test').digest();
  const otherMsg = createHash('sha256').update('test2').digest();
  const signature = ECDSA.sign(privateKey, msg);
  expect(Buffer.isBuffer(signature)).toBe(true);
  expect(ECDSA.verify(publicKey, otherMsg, signature)).toBe(false);
});

test('Reject on signing with invalid key', () => {
  const msg = createHash('sha256').update('test').digest();
  const k4 = Buffer.from('test');
  const k192 = Buffer.from('000000000000000000000000000000000000000000000000', 'hex');
  const k384 = Buffer.from('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex');
  expect(() => {
    try {
      ECDSA.sign(k4, msg);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  expect(() => {
    try {
      ECDSA.sign(k192, msg);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  expect(() => {
    try {
      ECDSA.sign(k384, msg);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Reject on when verifying with invalid key ', () => {
  const privateKey = Buffer.alloc(32);
  privateKey.fill(1);
  const msg = createHash('sha256').update('test').digest();
  const signature = ECDSA.sign(privateKey, msg);
  expect(Buffer.isBuffer(signature)).toBe(true);
  expect(() => {
    try {
      ECDSA.verify(Buffer.from('test'), msg, signature);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Reject on when verifying invalid signature ', () => {
  const privateKey = Buffer.alloc(32);
  privateKey.fill(1);
  const publicKey = getPublic(privateKey);
  const msg = createHash('sha256').update('test').digest();
  const signature = ECDSA.sign(privateKey, msg);
  expect(Buffer.isBuffer(signature)).toBe(true);
  signature[0] ^= 1;
  expect(() => {
    try {
      ECDSA.verify(publicKey, msg, signature);
    } catch (err) {
      throw err;
    }
  }).toThrow();
});