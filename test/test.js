var hash = require('../');

describe('core-hash', function () {
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
});
