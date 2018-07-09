const getPublic = require('../../src/browser/getPublic');
const encrypt = require('../../src/browser/encrypt');
const decrypt = require('../../src/browser/decrypt');
const expect = require('expect');

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


describe('ECIES', () => {
  it('encrypt', async () => {
    const privateKeyB = Buffer.alloc(32);
    privateKeyB.fill(3);
    const publicKeyB = getPublic(privateKeyB);
    const enc = await encrypt(publicKeyB, Buffer.from('test'), encOpts);
    expect(enc.iv.equals(iv)).toBe(true);
  });
});
