const cryptoObj = crypto || msCrypto || {};
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function decrypt(iv, key, data) {
  const importAlgorithm = { name: 'AES-CBC' };
  const cryptoKey = await subtle.importKey('raw', key, importAlgorithm, false, ['decrypt']);
  const encAlgorithm = { name: 'AES-CBC', iv };
  const result = await subtle.decrypt(encAlgorithm, cryptoKey, data);
  return Buffer.from(new Uint8Array(result));
}

module.exports = decrypt;
