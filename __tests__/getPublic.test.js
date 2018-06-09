const getPublic = require('../src/node/getPublic');



test('Public key is Buffer', () => {
  const privateKey = Buffer(32);
  privateKey.fill(1);
  const publicKey = getPublic(privateKey);
  expect(Buffer.isBuffer(publicKey)).toBe(true);
});

test('Private key can generate public key', () => {
  const privateKey = Buffer(32);
  privateKey.fill(1);
  const publicKey = getPublic(privateKey);
  expect(publicKey.toString("hex")).toEqual("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1");
})

test('Invalid key length hex', () => {
  expect(() => {
    try {
      getPublic(Buffer.from('00', 'hex'))
    } catch(err) {
      throw err;
    }
  }).toThrow();
})

test('Invalid key length', () => {
  expect(() => {
    try {
      getPublic(Buffer.from('test'))
    } catch(err) {
      throw err;
    }
  }).toThrow();
})
