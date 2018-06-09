function decrypt(privateKey, opts) {
  derive(privateKey, opts.ephemPublicKey).then((Px) => {
    const hash = sha512(Px);
    const encryptionKey = hash.slice(0, 32);
    const macKey = hash.slice(32);
    const dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext,
    ]);
    const realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), 'Bad MAC');
    return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
}