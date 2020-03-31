const test = require('tape')
const {
  Identity,
  puzzleEncrypt,
  puzzleBreak,
  puzzleOpen
} = require('..')

test('summons an decentralized Identity', t => {
  const id = new Identity()
  t.ok(id.master)
  t.ok(id.sig.pub)
  t.ok(id.sig.sec)
  t.ok(id.box.pub)
  t.ok(id.box.sec)
  t.end()
})

test('summon password protected Identity')
test('LabyrinthBox', t => {
  const org = Buffer.from('Hello Void')
  const box = puzzleEncrypt(org)
  const { data, pw } = puzzleBreak(box)
  t.ok(data.equals(org), 'Puzzlebox forced open')
  const d2 = puzzleOpen(box, pw)
  t.ok(d2.equals(org), 'Puzzlebox reopened nicely')
  t.end()
})
test('construct lvl0 void cache', t => {
  /** TROLL PHYSICS
   * PoW Difficulty is measured in time units taken to
   * to bruteforce a signature with N-leading zeros.
   * Proof of Work works because of 'belief' in the value of work.
   * Let's do that wrong, and instead say.
   *
   * 1. Encrypt secret with random 4 digits.
   * 2. Tell people there is a secret inside.
   * 3. Watch the believers waste time & electricity trying bruteforce the pass.
   * 4. ...
   * 5. Profit!
   */
  t.end()
})
test('construct lvl2 void cache')
test('draw 4 layered seal containing a public secret')
test('')
