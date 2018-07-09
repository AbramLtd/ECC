const cryptoObj = crypto || msCrypto || {};
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function encrypt(iv, key, data) {
  console.log(iv, key, data);
  const importAlgorithm = { name: 'AES-CBC' };
  const cryptoKey = await subtle.importKey('raw', key, importAlgorithm, false, ['encrypt']);
  console.log(cryptoKey);
  const encAlgorithm = { name: 'AES-CBC', iv };
  const result = await subtle.encrypt(encAlgorithm, cryptoKey, data);
  return Buffer.from(new Uint8Array(result));
}

module.exports = encrypt;
