const T = require('./sim-engine.js'), assert = require('assert');
const now = 12 * 3600;                         // "12:00"
// Japan-like item: restock every 2 h, next one at 13:25, stock 400 now, 20/min depletion, restock 1500, sells out in 75 min
const it = { qty: 400, cost: 100, market: 200, cadenceMin: 120, lastRestockAt: now - 35 * 60, nextRestockAt: now + 85 * 60, restockQty: 1500,
  depletionNow: 20, depletionMed: 20, sellOutSec: 75 * 60, nextConfidence: 0.8 };
const P = { carry: 27, cash: 0, buffer: 60 };
// restock times: 13:25, 15:25, 17:25, 19:25
assert.deepStrictEqual(T.restockTimes(it, now, now + 8 * 3600).map(r => (r.at - now) / 60), [85, 205, 325, 445]);
// the user's case: away until 18:20 (6h20 later) -> stock at landing 18:20 comes from the 17:25 restock (k=3), not from the 13:25 one
const f = T.forecastStock(it, now, now + 380 * 60);
assert.strictEqual(f.k, 3); assert.strictEqual(f.restockAt, now + 325 * 60);
assert.strictEqual(f.qty, 1500 - 20 * 55);     // 400 left after 55 min of selling
// leave now, land in 20 min: current stock lasts (400-20*20=0 -> sold out exactly) => needs restock
const a = T.decide(it, P, now, now, 20 * 60);
assert.strictEqual(a.avail, 'restock'); assert.strictEqual(a.restockAt, now + 85 * 60); assert.strictEqual(a.departAt, now + 85 * 60 + 60 - 20 * 60);
// I can only leave at 18:20 (start), flight 20 min -> land 18:40: sold again since 17:25 + 75 min = 18:40 -> must wait for the 19:25 restock
const b = T.decide(it, P, now, now + 380 * 60, 20 * 60);
assert.strictEqual(b.avail, 'restock'); assert.strictEqual(b.restockAt, now + 445 * 60); assert.strictEqual(b.k, 4);
assert(b.conf < 0.8 && b.conf > 0.4, 'confidence decays with the cycle');
// leave 18:00 land 18:15: stock from 17:25 restock still there (50 min sold)
const c = T.decide(it, P, now, now + 360 * 60, 15 * 60);
assert.strictEqual(c.avail, 'now'); assert(c.units === 27 && c.k === 3);
// no cadence -> only current stock
const d = T.decide({ qty: 900, cost: 1, depletionNow: 10 }, P, now, now, 600);
assert.strictEqual(d.avail, 'now'); assert.strictEqual(T.decide({ qty: 0, cost: 1 }, P, now, now, 600).avail, 'none');
// ---- history check
const hist = [[100, 500], [1000, 300], [2000, 0], [3000, 1500]];
assert.strictEqual(T.stockAt(hist, 1500, 10, 27, true).verdict, 'in');
assert.strictEqual(T.stockAt(hist, 2500, 10, 27, true).verdict, 'out');
assert.strictEqual(T.stockAt(hist, 1995, 10, 27, true).verdict, 'uncertain');   // sold out 5 s later: inside the +-10 s margin
assert.strictEqual(T.stockAt(hist, 50, 10, 1, true).verdict, 'nodata');
assert.strictEqual(T.stockAt(hist, 1500, 10, 1, false).verdict, 'nodata');
// ---- follow
const flights = [{ country: 'Japan', direction: 'out', takeoffAt: 1000, plane: 'Airstrip' }, { country: 'Japan', direction: 'return', takeoffAt: 1000 + 9000, plane: 'Airstrip' },
  { country: 'Japan', direction: 'out', takeoffAt: 1000 + 9100, plane: 'Airstrip' }];
const ctx = { ourPlane: 'Airstrip', dur: () => 8946, items: () => [{ id: 1, name: 'Plushie' }], hist: () => [[0, 100], [1000 + 30 + 8946 + 40, 0]], cover: () => [1000 + 30 + 8946] };
const trips = T.simulateFollow({ delay: 30, margin: 30 }, flights, ctx);
assert.strictEqual(trips[0].ourTakeoff, 1030); assert.strictEqual(trips[0].landing, 1030 + 8946);
assert.strictEqual(trips[0].checks[0].verdict, 'uncertain');      // stock hits 0 at landing+40 s: inside the +-30 s margin (+10 s freshness) -> uncertain
console.log('engine ok', trips.length, trips[0].checks[0], trips[1] && trips[1].skipped);
