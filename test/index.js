const test = require('tape')
const {
  Identity,
  Poll,
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

test('Ballot', t => {
  const W = new Identity()
  const A = new Identity()
  const poll = new Poll(null, { secretKey: W.sig.sec })
  poll.setChallenge(W.box.pub, {
    motion: 'How are you today?',
    options: ['Good', 'Ok', 'meh', 'had better']
  })
  t.equal(poll.challenge.motion, 'How are you today?')
  t.equal(poll.challenge.options[0], 'Good')
  t.ok(poll.challenge.ends_at)
  const share = poll.pickle()
  const rpoll = new Poll(share) // replicated

  t.equal(rpoll.challenge.motion, poll.challenge.motion)
  t.ok(rpoll.challenge.box_pk.equals(poll.challenge.box_pk))
  t.notOk(rpoll.secretKey)
  const receipt = rpoll.vote(A, Buffer.from([0]))
  debugger
  t.end()
})

test('PuzzleBox', t => {
  const org = Buffer.from('Hello Void')
  const box = puzzleEncrypt(org)
  const { data, pw } = puzzleBreak(box)
  t.ok(data.equals(org), 'Puzzlebox forced open')
  const d2 = puzzleOpen(box, pw) // takes about 8s on avg to break open
  t.ok(d2.equals(org), 'Puzzlebox reopened nicely')
  t.end()
})

test('construct lvl2 void cache')
test('draw 4 layered seal containing a public secret')
test('')
