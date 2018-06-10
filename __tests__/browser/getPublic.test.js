const getPublic = require('../../src/browser/getPublic');
const assert = require('assert');

describe('Get public key', () => {
  it('Public key is a Buffer', () => {
    const privateKey = Buffer.alloc(32);
    privateKey.fill(1);
    const publicKey = getPublic(privateKey);
    assert.equal(Buffer.isBuffer(publicKey), true);
  });
});
