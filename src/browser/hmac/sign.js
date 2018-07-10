const cryptoObj = crypto || msCrypto || {};
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function sign(key, msg) {
  const algorithm = {name: "HMAC", hash: {name: "SHA-256"}};
  const cryptoKey = await subtle.importKey("raw", key, algorithm, false, ["sign"]);
  const sig = await subtle.sign(algorithm, cryptoKey, msg);
  return new Buffer(new Uint8Array(sig));
}

module.exports = sign;