const ecdh = require('../../build/Release/ecdh'); // eslint-disable-line import/no-unresolved

function derive(privateKeyA, publicKeyB) {
  return ecdh.derive(privateKeyA, publicKeyB);
}

module.exports = derive;

