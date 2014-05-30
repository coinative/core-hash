var hash = require('../');

describe('core-hash', function () {
  it('hash160', function () {
    expect(hash.hash160('abc').toString('hex'))
      .to.equal('bb1be98c142444d7a56aa3981c3942a978e4dc33');
  });

  it('hash256', function () {
    expect(hash.hash256('abc').toString('hex'))
      .to.equal('4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358');
  });

  it('hmacsha512', function () {
    expect(hash.hmacsha512('Hi There', new Buffer('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')).toString('hex'))
      .to.equal('87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');
  });
});
