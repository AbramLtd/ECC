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

  it('decrypt', async () => {
    const privateKeyB = Buffer.alloc(32);
    privateKeyB.fill(3);
    const msg = await decrypt(privateKeyB, decOpts);
    expect(msg.toString()).toEqual('test');
  });
  
  it('encrypt and decrypt', async () => {
    const privateKeyA = Buffer.alloc(32);
    privateKeyA.fill(2);
    const publicKeyA = getPublic(privateKeyA);
  
    const privateKeyB = Buffer.alloc(32);
    privateKeyB.fill(3);
    console.log(publicKeyA, Buffer.from('secret'));
    const enc = await encrypt(publicKeyA, Buffer.from('secret'));
    console.log(enc);
    const msg = await decrypt(privateKeyA, enc);
    expect(msg.toString()).toEqual('secret');
  });
  
  it('Fail at bad private key when decrypting', () => {
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
  
  it('Fail on bad IV when decrypting', () => {
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
  
  it('Fail on bad R when decrypting', () => {
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
  
  it('Fail on bad ciphertext when decrypting', () => {
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
  
  it('Fail on bad MAC when decrypting', () => {
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
  
});
