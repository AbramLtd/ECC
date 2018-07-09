const getPublic = require('../../src/browser/getPublic');
const expect = require('expect');

describe('Get public key', () => {
  it('Public key is a Buffer', () => {
    const privateKey = Buffer.alloc(32);
    privateKey.fill(1);
    const publicKey = getPublic(privateKey);
    expect(Buffer.isBuffer(publicKey)).toBe(true);
  });

  it('Private key can generate public key', () => {
    const privateKey = Buffer.alloc(32);
    privateKey.fill(1);
    const publicKey = getPublic(privateKey);
    expect(publicKey.toString('hex')).toEqual('041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1');
  });

  it('Invalid key length hex', () => {
    expect(() => {
      try {
        getPublic(Buffer.from('00', 'hex'));
      } catch (err) {
        throw err;
      }
    }).toThrow();
  });
  
  it('Invalid key length', () => {
    expect(() => {
      try {
        getPublic(Buffer.from('test'));
      } catch (err) {
        throw err;
      }
    }).toThrow();
  });
  
});
