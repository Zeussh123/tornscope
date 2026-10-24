const S = require('./stock-insights.js'), assert = require('assert');
// synthetic: restock of 1500 every 2h at :00, depletion 227/min until empty
const T0 = Date.UTC(2026, 9, 24, 0, 0) / 1000, samples = [];
for (let h = 0; h < 12; h++) for (let m = 0; m < 120; m += 2) {
  const t = T0 + h * 7200 + m * 60, q = Math.max(0, Math.round(1500 - 227 * m)); samples.push({ t, qty: q });
}
const now = T0 + 11 * 7200 + 40 * 60, a = S.analyse(samples, { now });
assert(a.qty >= 1450 && a.qty <= 1500, 'restock qty ' + a.qty);
assert.strictEqual(Math.round(a.delayH), 2);
assert(a.sellOutMin >= 5 && a.sellOutMin <= 8, 'sellout ' + a.sellOutMin);
assert.strictEqual(a.confidence, 'high');
const v = S.verdict(a, now + 28 * 60, 1, now); // lands in 28 min, restock in ~80 min -> out
console.log(a, v);
