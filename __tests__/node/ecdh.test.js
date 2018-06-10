const derive = require('../../src/node/derive');
const getPublic = require('../../src/node/getPublic');

test('Derive shared secret from privkey A and pubkey B', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);

  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const publicKeyB = getPublic(privateKeyB);
  const px = derive(privateKeyA, publicKeyB);
  expect(Buffer.isBuffer(px)).toBe(true);
  expect(px.length).toEqual(32);
  expect(px.toString('hex')).toEqual('aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886');
  const px2 = derive(privateKeyB, publicKeyA);
  expect(Buffer.isBuffer(px2)).toBe(true);
  expect(px2.length).toEqual(32);
  expect(px.equals(px2)).toBe(true);
});

test('Reject bad keys', () => {
  const privateKeyA = Buffer.alloc(32);
  privateKeyA.fill(2);
  const publicKeyA = getPublic(privateKeyA);

  const privateKeyB = Buffer.alloc(32);
  privateKeyB.fill(3);
  const publicKeyB = getPublic(privateKeyB);
  expect(() => {
    try {
      derive(Buffer.from('test'), publicKeyB);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  expect(() => {
    try {
      derive(publicKeyB, publicKeyB);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  expect(() => {
    try {
      derive(privateKeyA, privateKeyA);
    } catch (err) {
      throw err;
    }
  }).toThrow();
  expect(() => {
    try {
      derive(privateKeyB, Buffer.from('test'));
    } catch (err) {
      throw err;
    }
  }).toThrow();
});

test('Fail on bad arguments', () => {
  expect(() => {
    try {
      derive({}, {});
    } catch (err) {
      throw err;
    }
  }).toThrow();
});
