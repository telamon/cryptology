const test = require('tape')
const {
  Identity,
  Poll,
  puzzleEncrypt,
  puzzleBreak,
  puzzleOpen,
  decrypt
} = require('..')

test('summons an decentralized Identity', t => {
  const id = new Identity()
  // t.ok(id.master) // Was moved to DerivedIdenty class
  t.ok(id.sig.pub)
  t.ok(id.sig.sec)
  t.ok(id.box.pub)
  t.ok(id.box.sec)
  t.end()
})

test('summon password protected Identity') // there will be a master key here

// No you should use this algorithm in real world
// scenarios, it has not been audited.
// this is a toy democratic encryption scheme.
test('Decentralized Poll agorithm', t => {
  const W = new Identity()
  const A = new Identity()
  const poll = new Poll(null, { secretKey: W.sig.sec })
  poll.packChallenge(W.box.pub, {
    motion: 'How are you today?',
    options: ['Good', 'Ok', 'meh', 'had better']
  })
  t.equal(poll.challenge.motion, 'How are you today?')
  t.equal(poll.challenge.options[0], 'Good')
  // t.ok(poll.challenge.ends_at)
  const share = poll.pickle()
  // Alice found the vote
  const rpoll = new Poll(share) // replicated

  t.equal(rpoll.challenge.motion, poll.challenge.motion)
  t.ok(rpoll.challenge.box_pk.equals(poll.challenge.box_pk))
  t.notOk(rpoll.secretKey)
  const aVote = Buffer.from([3])

  t.equal(rpoll.length, 1, '1 msg in feed')
  const receipt = rpoll.packVote(A, aVote)
  t.equal(rpoll.length, 2, 'ballot added')
  t.ok(rpoll.ballot)

  const aliceURL = rpoll.pickle()
  // Alice publishes her ballot
  console.log('file://dev/null#' + aliceURL)

  // Witness collects it
  const wpoll = new Poll(aliceURL)

  // Witness attempts to open the ballot
  // If b0 is not undefined, it means this ballot was addressed to us.
  const b0 = wpoll.unboxBallot(W.box.sec, W.box.pub)
  // b0 should equal to alice's receipt
  t.ok(receipt.equals(b0))

  // We can now read the vote though this is not the witness' job.
  t.ok(aVote.equals(wpoll._decryptVote(b0)))

  // Witness should publish the anonymized statement,
  // preferrably append it to a hypercore
  const bin = wpoll.toStatement(W.box.sec, W.box.pub)
  t.ok(bin)

  // Alice validates that her vote was recorded properly.
  const statement = Poll.Statement.decode(bin)
  t.ok(aVote.equals(statement.vote))
  const p = decrypt(statement.proof, receipt)
  t.ok(A.sig.pub.equals(p))
  // If alice's vote was recorded incorrectly,
  // at the cost of anonymity she can publish her receipt/b0
  // to prove that witness misbehaved having ignored her vote or manipulated it.

  // trace viral path
  /*
   * Out of scope for alpha.
  const B = new Identity() // Bob joins the fray!
  const bpoll = new Poll(aliceURL)
  // should see existing ballot.
  t.ok(bpoll.ballotKey.equals(A.sig.pub))
  t.equal(bpoll.ballotGen, 1)
  t.equal(bpoll.ballotPath.equals(bpoll.key))

  const bVote = Buffer.from([1])
  const breceipt = rpoll.packVote(B, bVote)
  debugger*/
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
