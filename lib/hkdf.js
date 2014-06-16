module.exports = function (hmac, hashLength) {
  return {
    extract: function (salt, ikm) {
      if (typeof salt === 'string') {
        salt = new Buffer(salt);
      }
      if (typeof ikm === 'string') {
        ikm = new Buffer(ikm);
      }
      return hmac(salt, ikm);
    },
    expand: function (prk, info, length) {
      if (typeof info === 'string') {
        info = new Buffer(info);
      }
      var prev = new Buffer(0);
      var output = new Buffer(0);
      var numBlocks = Math.ceil(length / hashLength);

      for (var i = 1; i <= numBlocks; i++) {
        prev = hmac(prk, Buffer.concat([prev, info, new Buffer([i])]));
        output = Buffer.concat([output, prev])
      }

      return output.slice(0, length);
    }
  }
};
