var crypto = require('crypto')
var b64url = require('base64-url')
var constantEqual = require('buffer-equal-constant-time')
var HKDF = require('./hkdf')

const DEFAULT_SECRET = crypto.randomBytes(32)
const DEFAULT_TIMEOUT = 5 * 60
const DEFAULT_HASH = 'sha256'
const HKDF_INFO_SIGNING = 'services.mozilla.com/tokenlib/v1/signing'
const HKDF_INFO_DERIVE = 'services.mozilla.com/tokenlib/v1/derive/'

function makeToken(obj, options) {
  options = options || {}
  options.secret = options.secret || DEFAULT_SECRET
  options.timeoutSeconds = options.timeoutSeconds || DEFAULT_TIMEOUT
  options.hash = options.hash || DEFAULT_HASH

  var data = JSON.parse(JSON.stringify(obj))
  data.salt = data.salt || crypto.randomBytes(3).toString('hex')
  data.expires = data.expires || getExpires(options.timeoutSeconds)
  var payload = Buffer(JSON.stringify(data))
  var sig = sign(payload, options.hash, options.secret)
  return b64url.encode(Buffer.concat([payload, sig]))
}

function parseToken(token, options) {
  options = options || {}
  options.secret = options.secret || DEFAULT_SECRET
  options.hash = options.hash || DEFAULT_HASH

  var decodedToken = decodeToken(token, options.hash)
  var mySig = sign(decodedToken.payload, options.hash, options.secret)
  if (!options.ignoreSig && !constantEqual(mySig, decodedToken.sig)) {
    throw new Error('Invalid Signature')
  }
  var data = JSON.parse(decodedToken.payload)
  if (!options.ignoreExpires && data.expires < (Date.now() / 1000)) {
    throw new Error('Expired Token')
  }
  return data
}

function derivedSecret(token, options) {
  options = options || {}

  var params = {
    secret: options.secret || DEFAULT_SECRET,
    hash: options.hash || DEFAULT_HASH,
    ignoreExpires: true
  }

  var salt = parseToken(token, params).salt
  var hkdf = new HKDF(params.hash, salt, params.secret)
  var secret = hkdf.derive(HKDF_INFO_DERIVE + token, hkdf.hashLength)
  return b64url.encode(secret)
}

function decodeToken(token, hash) {
  var sigLength = crypto.createHash(hash).digest().length
  var b = Buffer(token, 'base64')
  var payload = b.slice(0, -sigLength)
  var sig = b.slice(-sigLength)
  return {
    payload: payload,
    sig: sig
  }
}

function getExpires(timeoutSeconds) {
  return (Date.now() / 1000) + timeoutSeconds
}

function sign(payload, hash, secret) {
  var hkdf = new HKDF(hash, null, secret)
  var sigSecret = hkdf.derive(HKDF_INFO_SIGNING, hkdf.hashLength)
  return crypto.createHmac(hash, sigSecret)
   .update(payload)
   .digest()
}

module.exports = {
  makeToken: makeToken,
  parseToken: parseToken,
  decodeToken: decodeToken,
  derivedSecret: derivedSecret
}
