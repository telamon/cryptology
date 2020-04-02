// SPDX-License-Identifier: AGPL-3.0-or-later
const { PollMessage, PollStatement, IdentityMessage, VoteMsg } = require('./messages.js')
const PicoFeed = require('picofeed')
/* TODO: Rollup
const {
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_kdf_derive_from_key,
  crypto_kdf_keygen,

  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES,
  crypto_sign_BYTES,
  crypto_sign_seed_keypair,
  crypto_sign,
  crypto_sign_open,
  crypto_sign_detached,
  crypto_sign_verify_detached,

  crypto_box_MACBYTES,
  crypto_box_NONCEBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SEEDBYTES,
  crypto_box_seed_keypair,
  crypto_box_easy,
  crypto_box_open_easy,

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
} = require('sodium-universal') */
const sod = require('sodium-universal')

const Util = {
  deriveSubkey (master, n, context = '__undef__', id = 0) {
    if (!Buffer.isBuffer(context)) context = Buffer.from(context)
    const sub = Buffer.alloc(n)
    sod.crypto_kdf_derive_from_key(
      sub,
      id,
      context.subarray(0, sod.crypto_kdf_CONTEXTBYTES),
      master
    )
    return sub
  },

  deriveSignPair (master, ctx = 'IDENTITY', id = 0) {
    // crypto_sign_keypair  (crypto_sign_ed25519 this is what hypercore uses)
    const sec = Buffer.alloc(sod.crypto_sign_SECRETKEYBYTES) // U64
    const pub = Buffer.alloc(sod.crypto_sign_PUBLICKEYBYTES) // U32
    sod.crypto_sign_seed_keypair(
      pub,
      sec,
      Util.deriveSubkey(
        master,
        sod.crypto_sign_SEEDBYTES,
        ctx,
        id
      )
    )
    return { pub, sec }
  },

  deriveBoxPair (master, ctx = 'BOX00000', id = 0) {
    const sec = Buffer.alloc(sod.crypto_box_SECRETKEYBYTES) // U64
    const pub = Buffer.alloc(sod.crypto_box_PUBLICKEYBYTES) // U32
    sod.crypto_box_seed_keypair(
      pub,
      sec,
      Util.deriveSubkey(
        master,
        sod.crypto_box_SEEDBYTES || 32, // TODO: report missing const in browser.
        ctx,
        id
      )
    )
    return { pub, sec }
  },

  encrypt (data, encryptionKey, encode) {
    if (typeof encode === 'function') {
      data = encode(data)
    }
    if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'utf-8')

    const o = Buffer.allocUnsafe(data.length +
      sod.crypto_secretbox_NONCEBYTES +
      sod.crypto_secretbox_MACBYTES)

    const nonce = o.subarray(0, sod.crypto_secretbox_NONCEBYTES)
    sod.randombytes_buf(nonce)

    sod.crypto_secretbox_easy(
      o.subarray(sod.crypto_secretbox_NONCEBYTES),
      data, nonce, encryptionKey)
    return o
  },

  decrypt (buffer, encryptionKey, decode) {
    const message = Buffer.allocUnsafe(buffer.length -
      sod.crypto_secretbox_MACBYTES -
      sod.crypto_secretbox_NONCEBYTES)

    const nonce = buffer.subarray(0, sod.crypto_secretbox_NONCEBYTES)
    const success = sod.crypto_secretbox_open_easy(
      message,
      buffer.subarray(sod.crypto_secretbox_NONCEBYTES),
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
    const msgSig = Buffer.allocUnsafe(sod.crypto_sign_BYTES + m.length)
    sod.crypto_sign(msgSig, m, sk)
    return msgSig
  },

  signOpen (sm, pk) {
    const m = Buffer.allocUnsafe(sm.length - sod.crypto_sign_BYTES)
    if (!sod.crypto_sign_open(m, sm, pk)) throw new Error('Message failed signature authentication')
    return m
  },

  signDetached (message, secretKey) {
    const signature = Buffer.allocUnsafe(sod.crypto_sign_BYTES)
    sod.crypto_sign_detached(signature, message, secretKey)
    return signature
  },

  verifyDetached (message, signature, publicKey) {
    return sod.crypto_sign_verify_detached(signature, message, publicKey)
  },

  puzzleEncrypt (data, difficulty = 1) {
    if (difficulty > 3) throw new Error('Please mind the environment')
    const cipher = Buffer.allocUnsafe(data.length +
      sod.crypto_secretbox_MACBYTES +
      sod.crypto_secretbox_NONCEBYTES +
      sod.crypto_pwhash_SALTBYTES)
    const salt = cipher.subarray(0, sod.crypto_pwhash_SALTBYTES)
    const nonce = cipher.subarray(sod.crypto_pwhash_SALTBYTES,
      sod.crypto_pwhash_SALTBYTES + sod.crypto_secretbox_NONCEBYTES)
    const pw = Buffer.allocUnsafe(difficulty)
    sod.randombytes_buf(salt)
    sod.randombytes_buf(nonce)
    sod.randombytes_buf(pw)

    const secret = Buffer.allocUnsafe(sod.crypto_secretbox_KEYBYTES)

    sod.crypto_pwhash(secret, pw, salt,
      sod.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sod.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sod.crypto_pwhash_ALG_DEFAULT)

    sod.crypto_secretbox_easy(
      cipher.subarray(sod.crypto_pwhash_SALTBYTES + sod.crypto_secretbox_NONCEBYTES),
      data, nonce, secret)

    return cipher
  },

  puzzleBreak (comb, difficulty = 1, _knownKey = null) {
    // If you want higher difficulty then go play with PoW instead.
    // (or open an issue if you believe that I messed up)
    if (difficulty > 3) throw new Error('Please mind the environment')
    const salt = comb.subarray(0, sod.crypto_pwhash_SALTBYTES)
    const cipher = comb.subarray(sod.crypto_pwhash_SALTBYTES)
    const pw = Buffer.allocUnsafe(difficulty)
    const nonceLen = sod.crypto_secretbox_NONCEBYTES
    const nonce = cipher.subarray(0, nonceLen) // First part of the buffer
    const headerSz = sod.crypto_secretbox_MACBYTES +
      sod.crypto_secretbox_NONCEBYTES +
      sod.crypto_pwhash_SALTBYTES

    const messageLen = comb.length - headerSz

    const message = Buffer.allocUnsafe(messageLen)
    const secret = Buffer.allocUnsafe(sod.crypto_secretbox_KEYBYTES)
    let success = false

    const tried = []
    while (!success) { // TODO: maybe add timeout.
      sod.randombytes_buf(pw)
      // This does not work for higher diff
      // but i'm leaving it as is for now
      if (tried[pw[0]]) continue
      else tried[pw[0]] = true
      sod.crypto_pwhash(secret, _knownKey || pw, salt,
        sod.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sod.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sod.crypto_pwhash_ALG_DEFAULT)
      success = sod.crypto_secretbox_open_easy(
        message,
        comb.subarray(sod.crypto_pwhash_SALTBYTES + sod.crypto_secretbox_NONCEBYTES),
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

  // not supported in sodium-universal
  _box (to, from, m) {
    const o = Buffer.allocUnsafe(sod.crypto_box_MACBYTES +
      sod.crypto_box_NONCEBYTES +
      m.length)
    const n = o.subarray(0, sod.crypto_box_NONCEBYTES)
    sod.randombytes_buf(n)
    const c = o.subarray(sod.crypto_box_NONCEBYTES)
    sod.crypto_box_easy(c, m, n, to, from)
    return o
  },
  // not supported in sodium-universal
  _unbox (from, to, c) {
    const m = Buffer.allocUnsafe(c.length -
      sod.crypto_box_MACBYTES -
      sod.crypto_box_NONCEBYTES)
    const n = c.subarray(0, sod.crypto_box_NONCEBYTES)
    const succ = sod.crypto_box_open_easy(m, c.subarray(sod.crypto_box_NONCEBYTES), n, from, to)
    if (!succ) throw new Error('DecryptionFailedError')
    return m
  },
  seal (m, pk) {
    const c = Buffer.allocUnsafe(sod.crypto_box_SEALBYTES + m.length)
    sod.crypto_box_seal(c, m, pk)
    return c
  },
  unseal (c, sk, pk) {
    const m = Buffer.allocUnsafe(c.length - sod.crypto_box_SEALBYTES)
    const succ = sod.crypto_box_seal_open(m, c, pk, sk)
    if (!succ) throw new Error('DecryptionFailedError')
    return m
  }
}
module.exports = Util

module.exports.Identity = class Identity {
  constructor () {
    this.box = {
      pub: Buffer.allocUnsafe(sod.crypto_box_PUBLICKEYBYTES),
      sec: Buffer.allocUnsafe(sod.crypto_box_SECRETKEYBYTES)
    }
    sod.crypto_box_keypair(this.box.pub, this.box.sec)
    this.sig = {
      pub: Buffer.allocUnsafe(sod.crypto_sign_PUBLICKEYBYTES),
      sec: Buffer.allocUnsafe(sod.crypto_sign_SECRETKEYBYTES)
    }
    sod.crypto_sign_keypair(this.sig.pub, this.sig.sec)
  }

  static encode (id, b, o) {
    const m = {
      box: { sk: id.box.sec, pk: id.box.pub },
      sig: { sk: id.sig.sec, pk: id.sig.pub }
    }
    return IdentityMessage.encode(m, b, o).toString('base64')
  }

  static decode (buf, o, e) {
    if (typeof buf === 'string') buf = Buffer.from(buf, 'base64')
    const m = IdentityMessage.decode(buf, o, e)
    const id = new Identity()
    id.box.sec = m.box.sk
    id.box.pub = m.box.pk
    id.sig.sec = m.sig.sk
    id.sig.pub = m.sig.pk
    return id
  }
}

/* Work in progress.
module.exports.DerivedIdentity = class DerivedIdentity extends Identity {
  constructor (mk = null) {
    super()
    this.master = mk
    if (!this.master) {
      this.master = Buffer.alloc(sod.crypto_kdf_KEYBYTES)
      sod.crypto_kdf_keygen(this.master)
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

  packChallenge (pkey, { motion, options, endsAt }) {
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
    return this.get(Poll.CHALLENGE_IDX).challenge
  }

  get ballot () {
    return this.get(Poll.BALLOT_IDX).ballot
  }

  packVote (ident, vote, append = false) {
    if (!Buffer.isBuffer(vote)) throw new Error('vote must be a buffer')
    const b0 = Buffer.alloc(sod.crypto_secretbox_KEYBYTES)
    sod.randombytes_buf(b0)
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

  toStatement (sk, pk) {
    const b0 = this.unboxBallot(sk, pk)
    const stmt = {
      vote: this._decryptVote(b0),
      // If voter chooses to reveal b0, the statement becomes de-anonymized
      proof: Util.encrypt(this.ballot.box_pk, b0)
    }
    return PollStatement.encode(stmt)
  }
}
// Export for external use.
module.exports.Poll.Statement = PollStatement
module.exports.VoteMsg = VoteMsg
// fkc,
module.exports.sod = sod
if (typeof window !== 'undefined') {
  window.Cryptology = module.exports
}
