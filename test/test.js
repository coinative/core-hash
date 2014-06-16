var hash = require('../');

describe('satoshi-hash', function () {
  it('ripemd160', function () {
    expect(hash.ripemd160('abc').toString('hex'))
      .to.equal('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
  });

  it('sha256', function () {
    expect(hash.sha256('abc').toString('hex'))
      .to.equal('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('sha512', function () {
    expect(hash.sha512('abc').toString('hex'))
      .to.equal('ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
  });

  it('hash160', function () {
    expect(hash.hash160('abc').toString('hex'))
      .to.equal('bb1be98c142444d7a56aa3981c3942a978e4dc33');
  });

  it('hash256', function () {
    expect(hash.hash256('abc').toString('hex'))
      .to.equal('4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358');
  });

  it('hmacsha256', function () {
    expect(hash.hmacsha256(new Buffer('4a656665', 'hex'), new Buffer('7768617420646f2079612077616e7420666f72206e6f7468696e673f', 'hex')).toString('hex'))
      .to.equal('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  it('hmacsha512', function () {
    expect(hash.hmacsha512(new Buffer('4a656665', 'hex'), new Buffer('7768617420646f2079612077616e7420666f72206e6f7468696e673f', 'hex')).toString('hex'))
      .to.equal('164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737');
  });

  var hkdf256Vectors = [
    {
      input : '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      salt: '000102030405060708090a0b0c',
      info: 'f0f1f2f3f4f5f6f7f8f9',
      key: '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
      output: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    },
    {
      input : '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
      salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      key: '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
      output: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'
    },
    {
      input : '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      salt: '',
      info: '',
      key: '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
      output: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'
    }
  ];

  // https://tools.ietf.org/html/rfc5869
  describe('hkdf256', function () {
    hkdf256Vectors.forEach(function (vector, i) {
      it('vector ' + i, function () {
        var input = new Buffer(vector.input, 'hex');
        var salt = new Buffer(vector.salt, 'hex');
        var info = new Buffer(vector.info, 'hex');
        var key = hash.hkdf256.extract(salt, input);
        expect(key.toString('hex')).to.equal(vector.key);
        var output = hash.hkdf256.expand(key, info, vector.output.length / 2);
        expect(output.toString('hex')).to.equal(vector.output);
      });
    });
  });
});
