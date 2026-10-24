const S = require('./planner-position.js'), assert = require('assert');
const now = 1000000, dur = (c) => ({ Japan: 12780 * 0.7, Mexico: 1500 * 0.7 }[c] || 0);
// in Torn
assert.strictEqual(S.earliestDeparture({ state: 'torn' }, now, dur).at, now);
// flying home, lands in 10 min -> +30 s
assert.strictEqual(S.earliestDeparture({ state: 'flying', direction: 'return', landAt: now + 600 }, now, dur).at, now + 630);
// flying out to Mexico: land, +30 s, fly back
assert.strictEqual(S.earliestDeparture({ state: 'flying', direction: 'out', country: 'Mexico', landAt: now + 600 }, now, dur).at, now + 630 + 1050);
// planner: item in stock now, but I only leave in 10 min -> stock when I land is lower
const ST = { travelSec: { Mexico: { airstrip: 1050 } }, countries: [{ name: 'Mexico', code: 'mex', items: [{ id: 1, name: 'Xanax', type: 'Drug', qty: 1000, cost: 800000, market: 900000, depletionNow: 20, depletionMed: 20, emptiesAt: 0, nextRestockAt: 0, restockQty: 0 }] }] };
const P = { type: 'airstrip', carry: 27, cash: 0, sell: 95, buffer: 60, horizon: 8 };
const a = S.planRows(ST, P, now, now)[0], b = S.planRows(ST, P, now, now + 7200)[0];
assert(a.qtyLand > b.qtyLand, JSON.stringify([a.qtyLand, b.qtyLand, b.avail]));
assert(S.planRows(ST, P, now, now + 630)[0].departAt === now + 630);
const plan = S.dayPlan(S.planRows(ST, P, now, now + 630), P, now, now + 630);
assert(plan.trips[0].depart >= now + 630);
console.log('ok', a.qtyLand, b.qtyLand, plan.trips.length);
