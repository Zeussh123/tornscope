/* TornScope forecast + simulation engine. Pure functions (no DOM, no network, no database): the SAME source is
   injected into the Worker (simulations) and into the dashboard page (planner), so they can never disagree.
   Times are unix seconds. An "item" is a row of /api/radar/stock (qty, cost, market, lastRestockAt, cadenceMin, restockQty,
   nextRestockAt, nextConfidence, depletionNow, depletionMed, sellOutSec ...). */
/*ENGINE-BEGIN*/
const TSIM = (function () {
  'use strict';
  const HORIZON = 48 * 3600;      // we never forecast further than this
  const DECAY = 0.85;             // confidence lost for each extra restock cycle we extrapolate
  const median = (a) => { if (!a.length) return 0; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };

  // Restock moments after `now`: first = next one after now, then one every median gap. [{ at, k }] (k = 1, 2, 3 ...)
  function restockTimes(it, now, until) {
    const med = (it.cadenceMin || 0) * 60;
    if (!(med > 0)) return it.nextRestockAt > now && it.nextRestockAt <= until ? [{ at: it.nextRestockAt, k: 1 }] : [];   // no cadence known: only the announced next restock
    let first = it.nextRestockAt > now ? it.nextRestockAt : (it.lastRestockAt > 0 ? it.lastRestockAt + Math.max(1, Math.ceil((now - it.lastRestockAt) / med)) * med : 0);
    if (!(first > 0)) return [];
    const out = [];
    for (let t = first, k = 1; t <= until && t <= now + HORIZON && out.length < 40; t += med, k++) out.push({ at: t, k });
    return out;
  }

  // Stock we expect at time L (>= now): from the current stock if no restock comes before L, otherwise from the LAST restock before L.
  function forecastStock(it, now, L) {
    const rateNow = it.depletionNow > 0 ? it.depletionNow : (it.depletionMed || 0);
    const rateNew = it.depletionMed > 0 ? it.depletionMed : rateNow;
    const times = restockTimes(it, now, L);
    if (!times.length) {
      const qty = it.qty > 0 ? (rateNow > 0 ? Math.max(0, Math.floor(it.qty - rateNow * (L - now) / 60)) : it.qty) : 0;
      return { qty, k: 0, restockAt: 0 };
    }
    const last = times[times.length - 1], q0 = it.restockQty > 0 ? it.restockQty : Math.max(it.qty, 0);
    let qty = rateNew > 0 ? Math.max(0, Math.floor(q0 - rateNew * (L - last.at) / 60)) : q0;
    if (it.sellOutSec > 0 && L - last.at >= it.sellOutSec) qty = 0;
    return { qty, k: last.k, restockAt: last.at };
  }

  // Where would I be able to buy, if I can take off from Torn at `start`? P = { carry, cash, buffer }, dur = one-way seconds.
  // 'now'     : stock still there when I land (leave at start)   'restock' : wait for a (forecast) restock, leave later
  // 'late'    : sold out and no restock forecast                 'none'    : nothing known
  function decide(it, P, now, start, dur) {
    start = Math.max(now, start || now);
    const afford = P.cash > 0 ? Math.floor(P.cash / Math.max(1, it.cost)) : P.carry;
    const rateNew = it.depletionMed > 0 ? it.depletionMed : (it.depletionNow || 0);
    const land = start + dur;
    const f = forecastStock(it, now, land);
    const conf0 = it.nextConfidence || 0;
    if (f.qty > 0) {
      return { avail: 'now', departAt: start, units: Math.min(P.carry, afford, f.qty), qtyLand: f.qty, k: f.k, restockAt: f.restockAt, conf: f.k ? conf0 * Math.pow(DECAY, f.k - 1) : 1 };
    }
    // sold out when I would land: find the first restock I can still catch (land at least `buffer` s after it)
    const times = restockTimes(it, now, now + HORIZON);
    for (const r of times) {
      if (r.at + P.buffer < land) continue;                     // that restock will be over (sold again) before I can get there
      const departAt = Math.max(start, r.at + P.buffer - dur);
      const stockAtLand = Math.max(0, Math.floor((it.restockQty > 0 ? it.restockQty : P.carry) - (rateNew > 0 ? rateNew * Math.max(0, departAt + dur - r.at) / 60 : 0)));
      if (stockAtLand <= 0) return { avail: 'late', departAt: 0, units: 0, qtyLand: 0, k: r.k, restockAt: r.at, conf: 0 };
      return { avail: 'restock', departAt, units: Math.min(P.carry, afford, stockAtLand), qtyLand: stockAtLand, k: r.k, restockAt: r.at, conf: conf0 * Math.pow(DECAY, r.k - 1) };
    }
    return { avail: it.qty > 0 || times.length ? 'late' : 'none', departAt: 0, units: 0, qtyLand: 0, k: 0, restockAt: 0, conf: 0 };
  }

  // ---------- history checks (simulations) ----------
  // hist = [[ts, qty], ...] sorted, one row each time the quantity changed (plus one row before the window).
  const stateAt = (hist, t) => { let q = null; for (let i = 0; i < hist.length; i++) { if (hist[i][0] <= t) q = hist[i][1]; else break; } return q; };

  // Stock when I land at L: verdict in | out | uncertain (the answer changes inside +-margin: the data are only ~1 min precise) | nodata.
  // covered = was the feed alive around L (some stock change of this country within coverSec)?
  function stockAt(hist, L, margin, need, covered) {
    const q = stateAt(hist, L);
    if (q === null) return { verdict: 'nodata', qty: null, lo: null, hi: null };
    const s = [stateAt(hist, L - margin), q, stateAt(hist, L + margin)].filter(v => v !== null);
    const lo = Math.min.apply(null, s), hi = Math.max.apply(null, s);
    let nextTs = 0; for (let i = 0; i < hist.length; i++) if (hist[i][0] > L) { nextTs = hist[i][0]; break; }
    const verdict = covered === false ? 'nodata' : lo >= need ? 'in' : hi < need ? 'out' : 'uncertain';
    return { verdict, qty: q, lo, hi, nextChangeIn: nextTs ? nextTs - L : null };
  }

  const hasRowNear = (times, L, sec) => { for (let i = 0; i < times.length; i++) if (Math.abs(times[i] - L) <= sec) return true; return false; };

  // Follow a player: we take off `delay` s after him (+-margin), on the same route, and come back when he does.
  // flights = [{ country, direction, plane, takeoffAt }] of that player, sorted. ctx = { dur(country, plane), items(country) -> [{id,name}],
  //   hist(country,itemId) -> rows, cover(country) -> [ts], need, ourPlane }
  function simulateFollow(p, flights, ctx) {
    const trips = []; let free = -Infinity;
    const margin = p.margin == null ? 30 : p.margin, delay = p.delay == null ? 30 : p.delay, need = p.need || 1;
    for (let i = 0; i < flights.length; i++) {
      const f = flights[i];
      if (f.direction === 'return' || !f.country) continue;
      const nextOut = flights.slice(i + 1).findIndex(g => g.direction !== 'return');
      const stop = nextOut < 0 ? flights.length : i + 1 + nextOut;
      const back = flights.slice(i + 1, stop).find(g => g.direction === 'return' && g.country === f.country);
      const ourTake = f.takeoffAt + delay, dur = ctx.dur(f.country, ctx.ourPlane);
      if (!dur) continue;
      if (ourTake < free) { trips.push({ player: f, skipped: 'we were still travelling', ourTakeoff: ourTake }); continue; }
      const land = ourTake + dur, covered = hasRowNear(ctx.cover(f.country), land, p.coverSec || 600);
      const checks = ctx.items(f.country).map(it => {
        const hist = ctx.hist(f.country, it.id), at = [-margin, 0, margin].map(o => stockAt(hist, land + o, p.fresh || 10, need, covered));
        const worst = at.some(a => a.verdict === 'nodata') ? 'nodata' : at.every(a => a.verdict === 'in') ? 'in' : at.every(a => a.verdict === 'out') ? 'out' : 'uncertain';
        return { id: it.id, name: it.name, verdict: worst, qty: at[1].qty, lo: Math.min.apply(null, at.map(a => a.lo == null ? 0 : a.lo)) };
      });
      const theirReturn = back ? back.takeoffAt : null;
      const ourReturn = theirReturn ? Math.max(theirReturn + delay, land + 30) : null;
      const home = ourReturn ? ourReturn + dur : null; if (home) free = home + 30;
      trips.push({ player: f, ourTakeoff: ourTake, landing: land, covered, checks, theirReturn, ourReturn, home,
        followedReturn: !!back, lateOnSite: !!(theirReturn && land > theirReturn + delay) });
    }
    return trips;
  }

  // Forecast quality: at time T0 build the item as the site would have known it, decide, then look at what really happened.
  function statsAsOf(events, cycles, hist, T0, qtyNow) {
    const ev = events.filter(t => t <= T0 && t >= T0 - 14 * 86400);
    const gaps = []; for (let i = 1; i < ev.length; i++) gaps.push(ev[i] - ev[i - 1]);
    const med = median(gaps), last = ev.length ? ev[ev.length - 1] : 0;
    const cyc = cycles.filter(c => c.start <= T0 && c.start >= T0 - 7 * 86400), done = cyc.filter(c => c.soldout > c.start && c.soldout <= T0);
    const depMed = median(done.map(c => c.qty * 60 / (c.soldout - c.start)));
    let depNow = 0; { const r = hist.filter(x => x[0] <= T0 && x[0] >= T0 - 300); if (r.length >= 2 && r[0][1] > r[r.length - 1][1] && r[r.length - 1][0] - r[0][0] >= 20) depNow = (r[0][1] - r[r.length - 1][1]) * 60 / (r[r.length - 1][0] - r[0][0]); }
    const dev = gaps.map(g => Math.abs(g - med)).sort((a, b) => a - b), mad = dev.length ? dev[dev.length >> 1] : 0;
    return { qty: qtyNow, cadenceMin: med ? Math.round(med / 60) : 0, lastRestockAt: last, restockQty: Math.round(median(cyc.map(c => c.qty))), sellOutSec: Math.round(median(done.map(c => c.soldout - c.start))),
      depletionMed: Math.round(depMed * 10) / 10, depletionNow: Math.round(depNow * 10) / 10, nextRestockAt: 0,
      nextConfidence: med ? Math.round(Math.min(1, gaps.length / 6) * Math.max(0, 1 - 2 * mad / med) * 100) / 100 : 0, restocks: ev.length };
  }

  return { restockTimes, forecastStock, decide, stockAt, simulateFollow, statsAsOf, stateAt, hasRowNear, median };
})();
/*ENGINE-END*/
if (typeof module !== 'undefined' && module.exports) module.exports = TSIM;
