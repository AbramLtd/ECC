function pad32(msg) {
  let buf;
  if (msg.length < 32) {
    buf = Buffer.alloc(32);
    buf.fill(0);
    msg.copy(buf, 32 - msg.length);
    return buf;
  }
  return msg;
}

module.exports = pad32;
