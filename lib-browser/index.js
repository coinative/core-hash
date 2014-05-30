var sjcl = require('core-sjcl');

var toBits = sjcl.codec.bytes.toBits;
var toBytes = sjcl.codec.bytes.fromBits;

var ripemd160 = sjcl.hash.ripemd160.hash;
var sha256 = sjcl.hash.sha256.hash;

function hash160(data) {
  if (Buffer.isBuffer(data)) {
    data = toBits(data);
  }
  var hash = ripemd160(sha256(data));
  return new Buffer(toBytes(hash));
}

function hash256(data) {
  if (Buffer.isBuffer(data)) {
    data = toBits(data);
  }
  var hash = sha256(sha256(data));
  return new Buffer(toBytes(hash));
}

function hmacsha512(data, key) {
  if (Buffer.isBuffer(data)) {
    data = toBits(data);
  }
  if (Buffer.isBuffer(key)) {
    key = toBits(key);
  }
  var hash = new sjcl.misc.hmac(key, sjcl.hash.sha512).encrypt(data);
  return new Buffer(toBytes(hash));
}

exports.hash160 = hash160;
exports.hash256 = hash256;
exports.hmacsha512 = hmacsha512;
