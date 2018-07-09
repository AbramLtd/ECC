const ec = require('elliptic').ec('secp256k1');

function derive(privateKeyA, publicKeyB) {
  if (!Buffer.isBuffer(privateKeyA) || !Buffer.isBuffer(publicKeyB)) {
    throw new Error('Malformed input');
  }
  if (privateKeyA.length !== 32) {
    throw new Error('Malformed private key');
  }

  if (publicKeyB.length !== 65 || publicKeyB[0] !== 4) {
    throw new Error('Malformed public key');
  }
  const keyA = ec.keyFromPrivate(privateKeyA);
  const keyB = ec.keyFromPublic(publicKeyB);
  const px = keyA.derive(keyB.getPublic());
  return Buffer.from(px.toArray());
}

module.exports = derive;
