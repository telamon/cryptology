// SPDX-License-Identifier: AGPL-3.0-or-later
const { PollMessage, PollStatement, IdentityMessage, VoteMsg } = require('./messages')
const PicoFeed = require('picofeed')
const { scrypt, syncScrypt } = require('scrypt-js')
/* eslint-disable camelcase */
const {
  crypto_kdf_CONTEXTBYTES,
  // crypto_kdf_KEYBYTES,
  crypto_kdf_derive_from_key,
  // crypto_kdf_keygen,

  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES,
  crypto_sign_BYTES,
  crypto_sign_seed_keypair,
  // crypto_sign_keypair,
  crypto_sign,
  crypto_sign_open,
  crypto_sign_detached,
  crypto_sign_verify_detached,

  crypto_box_MACBYTES,
  crypto_box_NONCEBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SEEDBYTES,
  crypto_box_keypair,
  crypto_box_seed_keypair,
  crypto_box_easy,
  crypto_box_open_easy,

  crypto_box_SEALBYTES,
  crypto_box_seal,
  crypto_box_seal_open,

  crypto_secretbox_MACBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_easy,
  crypto_secretbox_open_easy,

  crypto_pwhash_SALTBYTES,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash,

  randombytes_buf
} = require('sodium-universal')
const Util = module.exports

module.exports.deriveSubkey = function (master, n, context = '__undef__', id = 0) {
  if (!Buffer.isBuffer(context)) context = Buffer.from(context)
  const sub = Buffer.alloc(n)
  crypto_kdf_derive_from_key(
    sub,
    id,
    context.subarray(0, crypto_kdf_CONTEXTBYTES),
    master
  )
  return sub
}

module.exports.deriveSignPair = function (master, ctx = 'IDENTITY', id = 0) {
  // crypto_sign_keypair  (crypto_sign_ed25519 this is what hypercore uses)
  const sec = Buffer.alloc(crypto_sign_SECRETKEYBYTES) // U64
  const pub = Buffer.alloc(crypto_sign_PUBLICKEYBYTES) // U32
  crypto_sign_seed_keypair(
    pub,
    sec,
    Util.deriveSubkey(
      master,
      crypto_sign_SEEDBYTES,
      ctx,
      id
    )
  )
  return { pub, sec }
}

module.exports.deriveBoxPair = function (master, ctx = 'BOX00000', id = 0) {
  const sec = Buffer.alloc(crypto_box_SECRETKEYBYTES) // U64
  const pub = Buffer.alloc(crypto_box_PUBLICKEYBYTES) // U32
  crypto_box_seed_keypair(
    pub,
    sec,
    Util.deriveSubkey(
      master,
      crypto_box_SEEDBYTES || 32, // TODO: report missing const in browser.
      ctx,
      id
    )
  )
  return { pub, sec }
}

module.exports.randomBytes = function (length) {
  const b = Buffer.allocUnsafe(length)
  randombytes_buf(b)
  return b
}

module.exports.encrypt = function (data, encryptionKey, encode) {
  if (typeof encode === 'function') {
    data = encode(data)
  }
  if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'utf-8')

  const o = Buffer.allocUnsafe(data.length +
    crypto_secretbox_NONCEBYTES +
    crypto_secretbox_MACBYTES)

  const nonce = o.subarray(0, crypto_secretbox_NONCEBYTES)
  randombytes_buf(nonce)

  crypto_secretbox_easy(
    o.subarray(crypto_secretbox_NONCEBYTES),
    data, nonce, encryptionKey)
  return o
}

module.exports.decrypt = function (buffer, encryptionKey, decode) {
  const message = Buffer.allocUnsafe(buffer.length -
    crypto_secretbox_MACBYTES -
    crypto_secretbox_NONCEBYTES)

  const nonce = buffer.subarray(0, crypto_secretbox_NONCEBYTES)
  const success = crypto_secretbox_open_easy(
    message,
    buffer.subarray(crypto_secretbox_NONCEBYTES),
    nonce,
    encryptionKey)

  if (!success) {
    const err = new Error('DecryptionFailedError')
    err.type = err.message
    throw err
  }
  // Run originally provided encoder if any
  if (typeof decode === 'function') return decode(message, 0, message.length)
  return message
}

module.exports.btoa = function (input) {
  if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    return window.btoa(input)
  } else {
    if (typeof input === 'string') input = Buffer.from(input)
    return input.toString('base64')
  }
}

module.exports.atob = function (input) {
  if (typeof window !== 'undefined' && typeof window.atob === 'function') {
    return window.atob(input)
  } else {
    return Buffer.from(input, 'base64')
  }
}

module.exports.sign = function (m, sk) {
  const msgSig = Buffer.allocUnsafe(crypto_sign_BYTES + m.length)
  crypto_sign(msgSig, m, sk)
  return msgSig
}

module.exports.signOpen = function (sm, pk) {
  const m = Buffer.allocUnsafe(sm.length - crypto_sign_BYTES)
  if (!crypto_sign_open(m, sm, pk)) throw new Error('Message failed signature authentication')
  return m
}

module.exports.signDetached = function (message, secretKey) {
  const signature = Buffer.allocUnsafe(crypto_sign_BYTES)
  crypto_sign_detached(signature, message, secretKey)
  return signature
}

module.exports.verifyDetached = function (message, signature, publicKey) {
  return crypto_sign_verify_detached(signature, message, publicKey)
}

module.exports.puzzleEncrypt = function (data, difficulty = 1) {
  if (difficulty > 3) throw new Error('Please mind the environment')
  const crypto_pwhash_SALTBYTES = 8
  const cipher = Buffer.allocUnsafe(data.length +
    crypto_secretbox_MACBYTES +
    crypto_secretbox_NONCEBYTES +
    crypto_pwhash_SALTBYTES)

  const salt = cipher.subarray(0, crypto_pwhash_SALTBYTES)
  const nonce = cipher.subarray(crypto_pwhash_SALTBYTES,
    crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES)
  const pw = Buffer.allocUnsafe(difficulty)
  randombytes_buf(salt)
  randombytes_buf(nonce)
  randombytes_buf(pw)

  const secret = Buffer.allocUnsafe(crypto_secretbox_KEYBYTES)
  crypto_pwhash(secret, pw, salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_DEFAULT)


  crypto_secretbox_easy(
    cipher.subarray(crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES),
    data, nonce, secret)

  return cipher
}

module.exports.puzzleBreak = function (comb, difficulty = 1, _knownKey = null) {
  // If you want higher difficulty then go play with PoW instead.
  // (or open an issue if you believe that I messed up)
  if (difficulty > 3) throw new Error('Please mind the environment')
  const salt = comb.subarray(0, crypto_pwhash_SALTBYTES)
  const cipher = comb.subarray(crypto_pwhash_SALTBYTES)
  const pw = Buffer.allocUnsafe(difficulty)
  const nonceLen = crypto_secretbox_NONCEBYTES
  const nonce = cipher.subarray(0, nonceLen) // First part of the buffer
  const headerSz = crypto_secretbox_MACBYTES +
    crypto_secretbox_NONCEBYTES +
    crypto_pwhash_SALTBYTES

  const messageLen = comb.length - headerSz

  const message = Buffer.allocUnsafe(messageLen)
  const secret = Buffer.allocUnsafe(crypto_secretbox_KEYBYTES)
  let success = false

  const tried = []
  while (!success) { // TODO: maybe add timeout.
    randombytes_buf(pw)
    // This does not work for higher diff
    // but i'm leaving it as is for now
    if (tried[pw[0]]) continue
    else tried[pw[0]] = true
    crypto_pwhash(secret, _knownKey || pw, salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT)
    success = crypto_secretbox_open_easy(
      message,
      comb.subarray(crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES),
      nonce,
      secret
    )
    if (_knownKey) {
      if (success) return { data: message }
      else throw new Error('DecryptionFailedError')
    }
  }
  return { pw, data: message }
}

module.exports.puzzleOpen = function (comb, key) {
  return Util.puzzleBreak(comb, undefined, key)
}

// not supported in sodium-universal
module.exports._box = function (to, from, m) {
  const o = Buffer.allocUnsafe(crypto_box_MACBYTES +
    crypto_box_NONCEBYTES +
    m.length)
  const n = o.subarray(0, crypto_box_NONCEBYTES)
  randombytes_buf(n)
  const c = o.subarray(crypto_box_NONCEBYTES)
  crypto_box_easy(c, m, n, to, from)
  return o
}

// not supported in sodium-universal
module.exports._unbox = function (from, to, c) {
  const m = Buffer.allocUnsafe(c.length -
    crypto_box_MACBYTES -
    crypto_box_NONCEBYTES)
  const n = c.subarray(0, crypto_box_NONCEBYTES)
  const succ = crypto_box_open_easy(m, c.subarray(crypto_box_NONCEBYTES), n, from, to)
  if (!succ) throw new Error('DecryptionFailedError')
  return m
}

module.exports.seal = function (m, pk) {
  const c = Buffer.allocUnsafe(crypto_box_SEALBYTES + m.length)
  crypto_box_seal(c, m, pk)
  return c
}

module.exports.unseal = function (c, sk, pk) {
  const m = Buffer.allocUnsafe(c.length - crypto_box_SEALBYTES)
  const succ = crypto_box_seal_open(m, c, pk, sk)
  if (!succ) throw new Error('DecryptionFailedError')
  return m
}

module.exports.scrypt = function (passphrase, salt, n = 2048, r = 8, p = 1, dkLen = 32) {
  passphrase = Buffer.from(passphrase.normalize('NFKC'))
  salt = Buffer.from(typeof salt === 'string' ? salt.normalize('NFKC') : salt)
  return scrypt(passphrase, passphrase, n, r, p, dkLen)
}

module.exports.boxPair = function () {
  const pk = Buffer.allocUnsafe(crypto_box_PUBLICKEYBYTES)
  const sk = Buffer.allocUnsafe(crypto_box_SECRETKEYBYTES)
  crypto_box_keypair(pk, sk)
  return { pk, sk }
}

/* Work in progress.
module.exports.DerivedIdentity = class DerivedIdentity extends Identity {
  constructor (mk = null) {
    super()
    this.master = mk
    if (!this.master) {
      this.master = Buffer.alloc(crypto_kdf_KEYBYTES)
      crypto_kdf_keygen(this.master)
    }
    // Signing keys
    this.sig = Util.deriveSignPair(this.master)
    this.box = Util.deriveBoxPair(this.master)
  }

  sign (m) {
    if (!Buffer.isBuffer(m)) m = Buffer.from(m)
    return Util.sign(m, this.sig.sec)
  }
}
*/

module.exports.Poll = class Poll extends PicoFeed {
  static get CHALLENGE_IDX () { return 0 }
  static get BALLOT_IDX () { return 1 }
  constructor (buf, opts) {
    super(buf, { ...opts, contentEncoding: PollMessage })
  }

  packChallenge (pkey, opts) {
    const { motion, options, endsAt, version, motd, extra } = opts
    const msg = {
      challenge: {
        version: version || 1,
        box_pk: pkey,
        motion,
        options,
        ends_at: endsAt,
        motd,
        extra
      }
    }
    this.append(msg) // TODO: Should be this.set(0, msg)
  }

  get challenge () {
    return this.get(Poll.CHALLENGE_IDX).challenge
  }

  get ballot () {
    return this.get(Poll.BALLOT_IDX).ballot
  }

  packVote (ident, vote, append = false) {
    if (!Buffer.isBuffer(vote)) throw new Error('vote must be a buffer')
    const b0 = Buffer.alloc(crypto_secretbox_KEYBYTES)
    randombytes_buf(b0)
    const msg = {
      ballot: {
        // This is also annoying, the bpk was supposed to be published
        // as part of the box-proof, with seals we're just sharing the users
        // public box key for good or bad.
        box_pk: ident.box.pub,
        secret_vote: Util.encrypt(vote, b0),
        // sadly not supported in browser
        // box_msg: Util.box(this.challenge.box_pk, ident.box.sec, b0)
        box_msg: Util.seal(b0, this.challenge.box_pk)
      }
    }

    // Sanity check. Don't want to accidentally litter the world with undecryptable messages.
    const safetyUnpack = Util.decrypt(msg.ballot.secret_vote, b0)
    if (!vote.equals(safetyUnpack)) {
      console.log(`Expected: (${vote.length})`, vote.toString(),
        `\nto equal: (${safetyUnpack.length})`, safetyUnpack.toString())
      throw new Error('Internal error, encryption failed')
    }

    if (!append) this.truncateAfter(Poll.CHALLENGE_IDX)
    if (this.length !== 1) throw new Error('invalid length after truncation')
    this.append(msg, ident.sig.sec)
    return b0
  }

  unboxBallot (sk, pk) {
    const blt = this.ballot
    return Util.unseal(blt.box_msg, sk, pk)
    // sadly not supported in browser
    // return Util.unbox(blt.box_pk, wboxs, blt.box_msg)
  }

  _decryptVote (secret) {
    return Util.decrypt(this.ballot.secret_vote, secret)
  }

  get ballotKey () {
    let p = 2
    for (const key of this.keys) if (!--p) return key
    return null
  }

  toStatement (sk, pk) {
    const b0 = this.unboxBallot(sk, pk)
    const stmt = {
      vote: this._decryptVote(b0),
      // If voter chooses to reveal b0, the statement becomes de-anonymized
      proof: Util.encrypt(this.ballotKey, b0)
    }
    return PollStatement.encode(stmt)
  }
}
// Export for external use.
module.exports.Poll.Statement = PollStatement
module.exports.VoteMsg = VoteMsg
// module.exports.Buffer = Buffer
/*
if (typeof window !== 'undefined') {
  window.Cryptology = module.exports
}
*/
