const { puzzleEncrypt, puzzleBreak } = require('.')
console.time('generate')
const puzzles = ['one', 'two', 'three', 'four', 'five']
  .map(m => Buffer.from(m))
  .map(m => puzzleEncrypt(m))
console.timeEnd('generate')
let sum = 0
let min = Infinity
let max = 0
for (const p of puzzles) {
  const start = new Date().getTime()
  puzzleBreak(p)
  const dur = new Date().getTime() - start
  console.log('Opened in ms: ', dur)
  sum += dur
  min = Math.min(dur, min)
  max = Math.max(dur, max)
}

console.log('avg:', sum / puzzles.length)
console.log('min:', min)
console.log('max:', max)
