var crypto = require('crypto');

function ripemd160(data) {
  return crypto.createHash('ripemd160').update(data).digest();
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hash160(data) {
  return ripemd160(sha256(data));
}

function hash256(data) {
  return sha256(sha256(data));
}

function hmacsha512(data, key) {
  return crypto.createHmac('sha512', key).update(data).digest();
}

exports.hash160 = hash160;
exports.hash256 = hash256;
exports.hmacsha512 = hmacsha512;
