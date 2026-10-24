/* TornScope planner - "Use my position".
   Pure functions (no DOM / network), same maths as planRows()/dayPlan() of the dashboard, plus the player's own position.
   Rule: a flight cannot be started before the current one has ended + a minimum delay (default 30 s: time to open the travel page).
   pos = { state: 'torn' }
       | { state: 'flying', country, direction: 'out'|'return', landAt }   (landAt = unix seconds, from Torn travel status)
       | { state: 'abroad', country }                                       (landed, not yet back)
   dur(country) = one-way flight time in seconds for the chosen aircraft. */
(function (root) {
  'use strict';
  const DELAY = 30;

  // Earliest moment the player can take off FROM TORN (what every trip of the planner needs).
  function earliestDeparture(pos, now, dur, delay) {
    delay = delay == null ? DELAY : delay;
    if (!pos || pos.state === 'torn') return { at: now, why: 'You are in Torn: you can leave now.' };
    const ready = Math.max(now, (pos.landAt || 0) + delay);          // landed + time to open the travel page
    if (pos.state === 'flying' && pos.direction === 'return') return { at: ready, why: 'Landing in Torn, then ' + delay + ' s to open the travel page.' };
    const back = dur(pos.country) || 0;
    if (pos.state === 'flying') return { at: ready + back, why: 'Landing in ' + pos.country + ', then you must fly back.' };
    return { at: now + delay + back, why: 'You are in ' + pos.country + ': fly back first.' };
  }

  // Same as dashboard planRows() but the player leaves at `start` instead of `now`.
  // ST = stock payload, P = plan settings {type, carry, cash, sell, buffer, countries, types, q}
  function planRows(ST, P, now, start) {
    const out = [], q = String(P.q || '').trim().toLowerCase();
    start = Math.max(now, start || now);
    (ST.countries || []).forEach(c => {
      if (P.countries && P.countries.indexOf(c.name) < 0) return;
      const dur = (ST.travelSec && ST.travelSec[c.name] && ST.travelSec[c.name][P.type]) || 0; if (!dur) return;
      c.items.forEach(i => {
        if (P.types && P.types.indexOf(i.type || 'Other') < 0) return;
        if (q && i.name.toLowerCase().indexOf(q) < 0) return;
        const pu = i.market > 0 ? Math.round(i.market * P.sell / 100) - i.cost : null;
        const afford = P.cash > 0 ? Math.floor(P.cash / Math.max(1, i.cost)) : P.carry;
        const rate = i.depletionNow > 0 ? i.depletionNow : (i.depletionMed || 0);
        const land = start + dur;
        // stock left when I land if I leave at `start`
        const qtyLand = i.qty > 0 ? (rate > 0 ? Math.max(0, Math.floor(i.qty - rate * (land - now) / 60)) : i.qty) : 0;
        const soldBy = i.qty > 0 && ((i.emptiesAt > 0 && land >= i.emptiesAt) || qtyLand === 0);
        const leaveAt = i.nextRestockAt > 0 ? i.nextRestockAt + P.buffer - dur : 0;
        let avail = 'none', units = 0, departAt = 0;
        if (i.qty > 0 && !soldBy) { avail = 'now'; units = Math.min(P.carry, afford, qtyLand); departAt = start; }
        else if (i.nextRestockAt > 0) {
          departAt = Math.max(start, leaveAt);
          // leaving later than the restock + buffer is fine only while the new stock lasts
          const stockAtLand = i.restockQty > 0 ? i.restockQty - (rate > 0 ? rate * Math.max(0, departAt + dur - i.nextRestockAt) / 60 : 0) : P.carry;
          avail = stockAtLand > 0 ? 'restock' : 'late';
          units = avail === 'restock' ? Math.min(P.carry, afford, Math.floor(stockAtLand)) : 0;
        } else if (i.qty > 0) avail = 'late';
        const perHour = pu > 0 && units > 0 ? Math.round(units * pu / (2 * dur / 3600)) : 0;
        out.push(Object.assign({}, i, { country: c.name, code: c.code, key: c.code + '|' + i.id, dur, pu, avail, units, departAt, leaveAt, perHour, qtyLand, rate, tripProfit: pu > 0 ? units * pu : 0 }));
      });
    });
    return out;
  }

  // Greedy day plan starting at `start` (first take-off cannot be earlier). After each trip the player is back in Torn at `back`,
  // and the next take-off is back + delay.
  function dayPlan(rows, P, now, start, delay) {
    delay = delay == null ? DELAY : delay;
    start = Math.max(now, start || now);
    const end = now + P.horizon * 3600, used = {}, trips = [];
    let t = start;
    while (trips.length < 14) {
      let best = null;
      rows.forEach(r => {
        if (used[r.key] || r.units <= 0 || !(r.pu > 0)) return;
        let depart;
        if (r.avail === 'now') { if (t > start + 60 && !(r.emptiesAt > 0 && t + r.dur < r.emptiesAt)) return; depart = t; }
        else depart = Math.max(t, r.nextRestockAt + P.buffer - r.dur);
        const back = depart + 2 * r.dur; if (back > end) return;
        const score = r.units * r.pu / (back - t);
        if (!best || score > best.score) best = { r, depart, land: depart + r.dur, back, score };
      });
      if (!best) break;
      trips.push(best); used[best.r.key] = true; t = best.back + (trips.length ? delay : 0);
    }
    return { trips, total: trips.reduce((a, x) => a + x.r.units * x.r.pu, 0) };
  }

  const api = { DELAY, earliestDeparture, planRows, dayPlan };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.TornScopePlanner = api;
})(typeof self !== 'undefined' ? self : this);
