// SPDX-License-Identifier: AGPL-3.0-or-later
const sodium = require('sodium-universal')
const PicoFeed = require('picofeed')

const Util = {
  encrypt (data, encryptionKey, encode) {
    if (typeof encode === 'function') {
      data = encode(data)
    }
    if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'utf-8')
    const o = Buffer.allocUnsafe(sodium.crypto_secretbox_NONCEBYTES +
      sodium.crypto_secretbox_MACBYTES + data.length)
    const nonce = o.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(nonce)
    sodium.crypto_secretbox_easy(
      o.slice(sodium.crypto_secretbox_NONCEBYTES),
      data, nonce, encryptionKey)
    return o
  },

  deriveSubkey (master, n, context = '__undef__', id = 0) {
    if (!Buffer.isBuffer(context)) context = Buffer.from(context)
    const sub = Buffer.alloc(n)
    sodium.crypto_kdf_derive_from_key(
      sub,
      id,
      context.slice(0, sodium.crypto_kdf_CONTEXTBYTES),
      master
    )
    return sub
  },

  deriveSignPair (master, ctx = 'IDENTITY', id = 0) {
    // crypto_sign_keypair  (crypto_sign_ed25519 this is what hypercore uses)
    const sec = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES) // U64
    const pub = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES) // U32
    sodium.crypto_sign_seed_keypair(
      pub,
      sec,
      Util.deriveSubkey(
        master,
        sodium.crypto_sign_SEEDBYTES,
        ctx,
        id
      )
    )
    return { pub, sec }
  },

  deriveBoxPair (master, ctx = 'BOX00000', id = 0) {
    const sec = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES) // U64
    const pub = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES) // U32
    sodium.crypto_box_seed_keypair(
      pub,
      sec,
      Util.deriveSubkey(
        master,
        sodium.crypto_box_SEEDBYTES,
        ctx,
        id
      )
    )
    return { pub, sec }
  },

  decrypt (buffer, encryptionKey, decode) {
    const message = Buffer.allocUnsafe(buffer.length -
      sodium.crypto_secretbox_MACBYTES -
      sodium.crypto_secretbox_MACBYTES)
    const nonce = buffer.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const success = sodium.crypto_secretbox_open_easy(
      message,
      buffer.slice(sodium.crypto_secretbox_NONCEBYTES),
      nonce,
      encryptionKey)

    if (!success) throw new Error('DecryptionFailedError')
    // Run originally provided encoder if any
    if (typeof decode === 'function') return decode(message, 0, message.length)
    return message
  },

  btoa (input) {
    if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
      return window.btoa(input)
    } else {
      if (typeof input === 'string') input = Buffer.from(input)
      return input.toString('base64')
    }
  },

  atob (input) {
    if (typeof window !== 'undefined' && typeof window.atob === 'function') {
      return window.atob(input)
    } else {
      return Buffer.from(input, 'base64')
    }
  },

  sign (m, sk) {
    const msgSig = Buffer.allocUnsafe(sodium.crypto_sign_BYTES + m.length)
    sodium.crypto_sign(msgSig, m, sk)
    return msgSig
  },

  signOpen (sm, pk) {
    const m = Buffer.allocUnsafe(sm.length - sodium.crypto_sign_BYTES)
    if (!sodium.crypto_sign_open(m, sm, pk)) throw new Error('Message failed signature authentication')
    return m
  },

  signDetached (message, secretKey) {
    const signature = Buffer.allocUnsafe(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, message, secretKey)
    return signature
  },

  verifyDetached (message, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey)
  },

  puzzleEncrypt (data, difficulty = 1) {
    if (difficulty > 3) throw new Error('Please mind the environment')
    const cipher = Buffer.allocUnsafe(data.length +
      sodium.crypto_secretbox_MACBYTES +
      sodium.crypto_secretbox_NONCEBYTES +
      sodium.crypto_pwhash_SALTBYTES)
    const salt = cipher.subarray(0, sodium.crypto_pwhash_SALTBYTES)
    const nonce = cipher.subarray(sodium.crypto_pwhash_SALTBYTES,
      sodium.crypto_pwhash_SALTBYTES + sodium.crypto_secretbox_NONCEBYTES)
    const pw = Buffer.allocUnsafe(difficulty)
    sodium.randombytes_buf(salt)
    sodium.randombytes_buf(nonce)
    sodium.randombytes_buf(pw)

    const secret = Buffer.allocUnsafe(sodium.crypto_secretbox_KEYBYTES)

    sodium.crypto_pwhash(secret, pw, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT)

    sodium.crypto_secretbox_easy(
      cipher.subarray(sodium.crypto_pwhash_SALTBYTES + sodium.crypto_secretbox_NONCEBYTES),
      data, nonce, secret)

    return cipher
  },

  puzzleBreak (comb, difficulty = 1, _knownKey = null) {
    // If you want higher difficulty then go play with PoW instead.
    // (or open an issue if you believe that I messed up)
    if (difficulty > 3) throw new Error('Please mind the environment')
    const salt = comb.subarray(0, sodium.crypto_pwhash_SALTBYTES)
    const cipher = comb.subarray(sodium.crypto_pwhash_SALTBYTES)
    const pw = Buffer.allocUnsafe(difficulty)
    const nonceLen = sodium.crypto_secretbox_NONCEBYTES
    const nonce = cipher.subarray(0, nonceLen) // First part of the buffer
    const headerSz = sodium.crypto_secretbox_MACBYTES +
      sodium.crypto_secretbox_NONCEBYTES +
      sodium.crypto_pwhash_SALTBYTES

    const messageLen = comb.length - headerSz

    const message = Buffer.allocUnsafe(messageLen)
    const secret = Buffer.allocUnsafe(sodium.crypto_secretbox_KEYBYTES)
    let success = false

    const tried = []
    while (!success) { // TODO: maybe add timeout.
      sodium.randombytes_buf(pw)
      // This does not work for higher diff
      // but i'm leaving it as is for now
      if (tried[pw[0]]) continue
      else tried[pw[0]] = true
      sodium.crypto_pwhash(secret, _knownKey || pw, salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT)
      success = sodium.crypto_secretbox_open_easy(
        message,
        comb.subarray(sodium.crypto_pwhash_SALTBYTES + sodium.crypto_secretbox_NONCEBYTES),
        nonce,
        secret
      )
      if (_knownKey) return success ? message : undefined
    }
    return { pw, data: message }
  },
  puzzleOpen (comb, key) {
    return Util.puzzleBreak(comb, undefined, key)
  },

  box (to, from, m) {
    const o = Buffer.allocUnsafe(sodium.crypto_box_MACBYTES +
      sodium.crypto_box_NONCEBYTES +
      m.length)
    const n = o.subarray(0, sodium.crypto_box_NONCEBYTES)
    sodium.randombytes_buf(n)
    const c = o.subarray(sodium.crypto_box_NONCEBYTES)
    sodium.crypto_box_easy(c, m, n, to, from)
    return o
  },
  unbox (from, to, c) {
    const m = Buffer.allocUnsafe(c.lenght -
      sodium.crypto_box_MACBYTES -
      sodium.crypto_box_NONCEBYTES)
    const n = c.subarray(0, sodium.crypto_box_NONCEBYTES)
    const succ = sodium.crypto_box_open_easy(m, c, n, from, to)
    if (!succ) throw new Error('DecryptionFailedError')
    return m
  }

}
module.exports = Util

module.exports.Identity = class HyperIdentity {
  constructor (mk = null) {
    this.master = mk
    if (!this.master) {
      this.master = Buffer.alloc(sodium.crypto_kdf_KEYBYTES)
      sodium.crypto_kdf_keygen(this.master)
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

// Not sure if this is a poll or a void cache, time will tell.
const { PollMessage } = require('./messages.js')
module.exports.Poll = class VoidCache extends PicoFeed {
  static get CHALLENGE_IDX () { return 0 }
  static get BALLOT_IDX () { return 1 }
  constructor (buf, opts) {
    super(buf, { ...opts, contentEncoding: PollMessage })
  }

  setChallenge (pkey, { motion, options, endsAt }) {
    const msg = {
      challenge: {
        box_pk: pkey,
        motion,
        options,
        ends_at: endsAt || new Date().getTime() + 86400000
      }
    }
    this.append(msg) // TODO: Should be this.set(0, msg)
  }

  get challenge () {
    return this.get(VoidCache.CHALLENGE_IDX).challenge
  }

  get ballot () {
    return this.get(VoidCache.BALLOT_IDX).ballot
  }

  vote (ident, vote) {
    const b0 = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
    sodium.randombytes_buf(b0)
    const msg = {
      ballot: {
        box_pk: ident.box.pub,
        secret_vote: Util.encrypt(vote, b0),
        box_msg: Util.box(this.challenge.box_pk, ident.box.sec, b0)
      }
    }
    // TODO: this.trunc(1) // overwrite existing ballots.
    this.append(msg, ident.sig.sec)
    return b0
  }
}
