var crypto = require("crypto");

function zeros(length) {
  return Buffer(length).fill(0)
}

function HKDF(hashAlg, salt, ikm) {
  this.hashAlg = hashAlg

  // create the hash alg to see if it exists and get its length
  var hash = crypto.createHash(this.hashAlg)
  this.hashLength = hash.digest().length

  this.salt = salt || Buffer(this.hashLength).fill(0)
  this.ikm = ikm

  // now we compute the PRK
  var hmac = crypto.createHmac(this.hashAlg, this.salt)
  hmac.update(this.ikm)
  this.prk = hmac.digest()
}

HKDF.prototype = {
  derive: function(info, size) {
    info = Buffer(info)
    var prev = Buffer(0)
    var num_blocks = Math.ceil(size / this.hashLength)
    var blocks = []

    for (var i = 0; i < num_blocks; i++) {
      var hmac = crypto.createHmac(this.hashAlg, this.prk)
      var input = Buffer.concat([
        prev,
        info,
        Buffer([i + 1])
      ])
      hmac.update(input)
      prev = hmac.digest()
      blocks.push(prev)
    }
    return Buffer.concat(blocks, size)
  }
};

module.exports = HKDF;
