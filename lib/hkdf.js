module.exports = function (hmacSha, hashLength) {
  return {
    extract: function (salt, ikm) {
      if (typeof salt === 'string') {
        salt = new Buffer(salt);
      }
      if (typeof ikm === 'string') {
        ikm = new Buffer(ikm);
      }
      return hmacSha(salt, ikm);
    },
    expand: function (prk, info, length) {
      if (typeof info === 'string') {
        info = new Buffer(info);
      }
      var prev = new Buffer(0);
      var output = new Buffer(0);
      var num_blocks = Math.ceil(length / hashLength);

      for (var i=1; i<=num_blocks; i++) {
        prev = hmacSha(prk, Buffer.concat([prev, info, new Buffer([i])]));
        output = Buffer.concat([output, prev])
      }

      return output.slice(0, length);
    }
  }
};
