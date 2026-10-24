/* TornScope stock insights - pure functions, no DOM, no network (usable by the site, the Worker or the userscript).
   Input  : samples = [{ t: unixSeconds, qty: number }] sorted by time, for ONE country + item (e.g. YATA snapshots).
   Output : the figures shown on the tornw3b-style card (depletion rate, restock delay/qty, sell-out time,
            restock time of day, and a verdict for a given landing time). */
(function (root) {
  'use strict';
  const median = (a) => { if (!a.length) return 0; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

  // Split the history into restocks (qty jumps up) and depletion intervals (qty goes down).
  function parse(samples, jump) {
    const restocks = [], drops = [];
    for (let i = 1; i < samples.length; i++) {
      const a = samples[i - 1], b = samples[i], dt = (b.t - a.t) / 60;
      if (dt <= 0) continue;
      if (b.qty - a.qty >= jump) restocks.push({ t: b.t, qty: b.qty, from: a.qty, soldOutAt: a.qty <= jump ? a.t : 0 });
      else if (b.qty < a.qty) drops.push({ t: b.t, rate: (a.qty - b.qty) / dt });
    }
    return { restocks, drops };
  }

  function analyse(samples, opts) {
    opts = opts || {};
    const jump = opts.jump || 50, now = opts.now || Date.now() / 1000;
    const { restocks, drops } = parse(samples, jump);
    const rates = drops.map(d => d.rate);
    const recent = drops.filter(d => now - d.t <= 3600).map(d => d.rate);
    const rate = recent.length ? median(recent) : median(rates);          // current depletion /min
    const rateMed = median(rates);                                        // typical depletion /min
    const qty = Math.round(median(restocks.map(r => r.qty)));             // typical restock quantity
    const gaps = restocks.slice(1).map((r, i) => (r.t - restocks[i].t) / 3600);
    const delayH = median(gaps);                                          // hours between restocks
    const sellOutMin = rate > 0 && qty ? Math.round(qty / rate) : 0;      // minutes to empty a fresh restock
    // Restock time of day: most common minute-of-hour (+-10 min) = confidence.
    const mins = restocks.map(r => new Date(r.t * 1000).getMinutes());
    let best = { m: 0, n: 0 };
    mins.forEach(m0 => { const n = mins.filter(m => Math.min(Math.abs(m - m0), 60 - Math.abs(m - m0)) <= 10).length; if (n > best.n) best = { m: m0, n }; });
    const share = mins.length ? best.n / mins.length : 0;
    const confidence = mins.length < 5 ? 'low' : share >= 0.75 ? 'high' : share >= 0.5 ? 'fair' : 'low';
    const last = samples[samples.length - 1] || { t: now, qty: 0 };
    const lastRestock = restocks[restocks.length - 1];
    const nextRestock = lastRestock && delayH ? lastRestock.t + delayH * 3600 : 0;
    return { rate, rateMed, qty, delayH, sellOutMin, restockMinute: best.m, confidence, share, cycles: restocks.length, nextRestock, last };
  }

  // Will `want` items still be in stock when the player lands at `landAt` (unix seconds)?
  function verdict(a, landAt, want, now) {
    now = now || Date.now() / 1000; want = want || 1;
    if (!a.rate) return { code: 'unknown', text: 'Not enough data' };
    const restockBefore = a.nextRestock && a.nextRestock > now && a.nextRestock <= landAt;
    const base = restockBefore ? a.qty : a.last.qty - a.rate * Math.max(0, (now - a.last.t) / 60);
    const since = restockBefore ? (landAt - a.nextRestock) / 60 : (landAt - now) / 60;
    const left = Math.max(0, Math.round(base - a.rate * since));
    if (left >= want * 3) return { code: 'ok', left, text: restockBefore ? 'Restock lands before you: in stock' : 'Should still be in stock' };
    if (left >= want) return { code: 'risky', left, text: 'Tight: ~' + left + ' left when you land' };
    return { code: 'out', left, text: restockBefore ? 'Restocks before you land but likely sold out again' : 'Likely sold out when you land' };
  }

  // Money helper for "plan for N items": total + average per item.
  const cost = (price, n) => ({ total: price * n, each: price });

  const api = { analyse, verdict, cost, parse };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.TornScopeStock = api;
})(typeof self !== 'undefined' ? self : this);
