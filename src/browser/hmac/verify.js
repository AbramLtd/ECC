const cryptoObj = crypto || msCrypto || {};
const subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;

async function verify(key, msg, sig) {
  const algorithm = {name: "HMAC", hash: {name: "SHA-256"}};
  const cryptoKey = await subtle.importKey("raw", key, algorithm, false, ["verify"]);
  return subtle.verify(algorithm, cryptoKey, sig, msg);
}

module.exports = verify;