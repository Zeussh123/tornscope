/*PSIM-BEGIN*/
  /* ================= PAGE: simulations (admin) ================= */
  // Replays the recorded stock history to check what the planner / a followed player would have found on landing.
  // The data come from /admin/sim/data, the maths are TSIM (the planner's own engine), results are saved with /admin/sim/runs.
  const SIM_QUEUE = [];
  const SIM_PLANES = [['airstrip', 'Airstrip'], ['standard', 'Standard'], ['wlt', 'WLT'], ['business', 'Business']];
  const planeKeyOf = (name) => { const s = String(name || '').toLowerCase(); return /airstrip|light/.test(s) ? 'airstrip' : /wlt|jet|private/.test(s) ? 'wlt' : /business/.test(s) ? 'business' : 'standard'; };
  const SIM_LABEL = { follow: 'Follow a player', planner: 'Planner accuracy', check: 'Planned flights' };
  const simClock = (t) => { const d = new Date(t * 1000); return pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); };
  const simLocalInput = (t) => { const d = new Date(t * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  const simBadge = (v) => h('span', { class: 'badge ' + ({ in: 'ok', out: 'bad', uncertain: 'warn', nodata: '' }[v] || ''), text: { in: 'in stock', out: 'sold out', uncertain: 'uncertain', nodata: 'no data' }[v] || v });
  const simPct = (a, b) => b ? Math.round(100 * a / b) + '%' : '—';

  function simItems(data, country, top) {
    const c = data.countries[country]; if (!c) return [];
    const ranked = c.items.filter(i => i.market > 0).map(i => Object.assign({ pu: Math.round(i.market * 0.95) - i.cost }, i)).filter(i => i.pu > 0).sort((a, b) => b.pu - a.pu);
    return (ranked.length ? ranked : c.items).slice(0, top);
  }
  function simContext(data, p) {
    const cover = {}; Object.keys(data.hist).forEach(k => { const code = k.split('|')[0]; (cover[code] = cover[code] || []).push.apply(cover[code], data.hist[k].map(r => r[0])); });
    Object.keys(cover).forEach(c => cover[c].sort((a, b) => a - b));
    return { ourPlane: p.plane, need: p.need || 1,
      dur: (country, plane) => (data.travelSec[country] && data.travelSec[country][planeKeyOf(plane)]) || 0,
      items: (country) => simItems(data, country, p.top || 6),
      hist: (country, id) => data.hist[((data.countries[country] || {}).code) + '|' + id] || [],
      cover: (country) => cover[(data.countries[country] || {}).code] || [] };
  }

  function runFollow(p, data) {
    const ctx = simContext(data, p), trips = TSIM.simulateFollow(p, data.flights, ctx);
    const done = trips.filter(t => !t.skipped), cells = [].concat.apply([], done.map(t => t.checks));
    const n = (v) => cells.filter(c => c.verdict === v).length;
    return { summary: { trips: done.length, skipped: trips.length - done.length, itemChecks: cells.length, inStock: n('in'), soldOut: n('out'), uncertain: n('uncertain'), noData: n('nodata'), tripsWithStock: done.filter(t => t.checks.some(c => c.verdict === 'in')).length },
      rows: trips.map(t => ({ their: t.player.takeoffAt, country: t.player.country, ours: t.ourTakeoff, landing: t.landing || 0, skipped: t.skipped || '', covered: t.covered, checks: (t.checks || []).map(c => [c.name, c.verdict, c.qty]), theirReturn: t.theirReturn || 0, ourReturn: t.ourReturn || 0, home: t.home || 0, late: !!t.lateOnSite, followed: !!t.followedReturn })) };
  }

  async function runPlanner(p, data, tick) {
    const P = { carry: p.carry, cash: 0, buffer: p.buffer }, rows = [], keys = [];
    Object.keys(data.countries).forEach(cn => data.countries[cn].items.forEach(i => { if (i.market > 0 && Math.round(i.market * p.sell / 100) - i.cost > 0) keys.push({ cn, code: data.countries[cn].code, i, pu: Math.round(i.market * p.sell / 100) - i.cost }); }));
    const cover = simContext(data, p).cover;
    let step = 0;
    for (let T0 = p.from; T0 <= p.to; T0 += p.step * 60) {
      let best = null;
      for (const k of keys) {
        const key = k.code + '|' + k.i.id, hist = data.hist[key] || [], qty = TSIM.stateAt(hist, T0); if (qty === null) continue;
        const dur = (data.travelSec[k.cn] && data.travelSec[k.cn][p.plane]) || 0; if (!dur) continue;
        const it = Object.assign({ cost: k.i.cost }, TSIM.statsAsOf(data.events[key] || [], data.cycles[key] || [], hist, T0, qty));
        const d = TSIM.decide(it, P, T0, T0, dur); if (d.units <= 0) continue;
        const perHour = d.units * k.pu / (2 * dur / 3600);
        if (!best || perHour > best.perHour) best = { k, d, dur, perHour, key, hist };
      }
      if (best) {
        const L = best.d.departAt + best.dur, covered = L <= data.now && TSIM.hasRowNear(cover(best.k.cn), L, 600);   // a landing after "now" cannot be judged yet
        const full = TSIM.stockAt(best.hist, L, 10, best.d.units, covered), any = TSIM.stockAt(best.hist, L, 10, 1, covered);
        let err = null;
        if (best.d.k > 0) { const ev = (data.events[best.key] || []), near = ev.filter(t => Math.abs(t - best.d.restockAt) <= 3600).sort((a, b) => Math.abs(a - best.d.restockAt) - Math.abs(b - best.d.restockAt))[0]; if (near) err = near - best.d.restockAt; }
        rows.push({ t0: T0, country: best.k.cn, item: best.k.i.name, avail: best.d.avail, k: best.d.k, depart: best.d.departAt, land: L, units: best.d.units, forecastQty: best.d.qtyLand, conf: best.d.conf, actualQty: full.qty, full: full.verdict, any: any.verdict, restockErr: err });
      }
      if (++step % 15 === 0) { await new Promise(r => setTimeout(r, 0)); if (tick) tick(T0); }
    }
    const by = (f) => rows.filter(f), hit = (a) => a.filter(r => r.full === 'in').length, judged = (a) => a.filter(r => r.full === 'in' || r.full === 'out').length;
    const errs = rows.filter(r => r.restockErr !== null).map(r => Math.abs(r.restockErr) / 60);
    return { summary: { decisions: rows.length, hit: hit(rows), judged: judged(rows), hitNow: hit(by(r => r.avail === 'now')), judgedNow: judged(by(r => r.avail === 'now')), hitRestock: hit(by(r => r.avail === 'restock')), judgedRestock: judged(by(r => r.avail === 'restock')),
      uncertain: rows.filter(r => r.full === 'uncertain').length, noData: rows.filter(r => r.full === 'nodata').length, restockErrMedianMin: errs.length ? Math.round(TSIM.median(errs) * 10) / 10 : null, restockErrCount: errs.length }, rows };
  }

  function parseChecks(text, tzOffsetMin) {
    const out = [];
    String(text || '').split('\n').map(s => s.trim()).filter(Boolean).forEach(line => {
      const [country, when, plane] = line.split(';').map(s => s.trim()); const t = Math.floor(new Date((when || '').replace(' ', 'T')).getTime() / 1000);
      if (country && t > 0) out.push({ country, takeoffAt: t, plane: plane || 'Airstrip' });
    });
    return out;
  }
  function runCheck(p, data) {
    const ctx = simContext(data, p), rows = [];
    p.flights.forEach(f => {
      const dur = ctx.dur(f.country, f.plane), land = f.takeoffAt + dur, covered = TSIM.hasRowNear(ctx.cover(f.country), land, 600);
      const checks = !dur ? [] : ctx.items(f.country).map(it => { const a = [-p.margin, 0, p.margin].map(o => TSIM.stockAt(ctx.hist(f.country, it.id), land + o, p.fresh, p.need, covered)); const v = a.some(x => x.verdict === 'nodata') ? 'nodata' : a.every(x => x.verdict === 'in') ? 'in' : a.every(x => x.verdict === 'out') ? 'out' : 'uncertain'; return [it.name, v, a[1].qty]; });
      rows.push({ their: 0, country: f.country, ours: f.takeoffAt, landing: land, skipped: dur ? '' : 'unknown country or aircraft', covered, checks, theirReturn: 0, ourReturn: 0, home: land + dur, late: false, followed: false });
    });
    const cells = [].concat.apply([], rows.map(r => r.checks)), n = (v) => cells.filter(c => c[1] === v).length;
    return { summary: { trips: rows.length, skipped: 0, itemChecks: cells.length, inStock: n('in'), soldOut: n('out'), uncertain: n('uncertain'), noData: n('nodata'), tripsWithStock: rows.filter(r => r.checks.some(c => c[1] === 'in')).length }, rows };
  }

  async function simExecute(job, setStatus) {
    const p = job.params, q = (o) => Object.keys(o).map(k => k + '=' + encodeURIComponent(o[k])).join('&');
    let from = p.from, to = p.to;
    if (job.kind === 'check') { const ts = p.flights.map(f => f.takeoffAt); from = Math.min.apply(null, ts) - 600; to = Math.max.apply(null, ts); }
    const countries = job.kind === 'check' ? Array.from(new Set(p.flights.map(f => f.country))).join(',') : (p.countries || []).join(',');
    setStatus('Loading the recorded data…');
    const r = await api('GET', '/admin/sim/data?' + q({ kind: job.kind, from, to, player: p.player || '', countries }));
    if (!r.ok) throw new Error(r.data.message || 'Could not load the data');
    const data = r.data; if (job.kind === 'follow' && !data.flights.length) throw new Error('This player has no recorded flight in that period.');
    setStatus('Simulating…');
    const out = job.kind === 'follow' ? runFollow(p, data) : job.kind === 'check' ? runCheck(p, data) : await runPlanner(p, data, (t) => setStatus('Simulating… ' + simClock(t)));
    out.truncated = !!data.truncated;
    const saved = await api('POST', '/admin/sim/runs', { kind: job.kind, label: job.label, params: p, summary: out.summary, result: out });
    if (!saved.ok) throw new Error(saved.data.message || 'Could not save the result');
    return Object.assign({ id: saved.data.id }, out);
  }

  function simResultView(run) {
    const s = run.summary || {}, rows = (run.result && run.result.rows) || [], box = h('div');
    if (run.kind === 'planner') {
      box.appendChild(h('div', { class: 'grid cols-4' },
        stat('Decisions', String(s.decisions), 'one per step: the best trip the planner would have chosen'),
        stat('Stock really there', simPct(s.hit, s.judged), s.hit + ' of ' + s.judged + ' judged (full quantity on landing)'),
        stat('Leave-now trips', simPct(s.hitNow, s.judgedNow), 'restock trips: ' + simPct(s.hitRestock, s.judgedRestock)),
        stat('Restock timing error', s.restockErrMedianMin === null ? '—' : s.restockErrMedianMin + ' min', 'median over ' + s.restockErrCount + ' forecasts · ' + s.uncertain + ' uncertain · ' + s.noData + ' no data')));
      box.appendChild(h('div', { style: 'margin-top:12px' }, dataTable({ rows, defaultSort: 't0', defaultDir: 'asc', pageSize: 15, empty: empty('No decision'), cols: [
        { key: 't0', label: 'Planned at', render: r => simClock(r.t0) }, { key: 'country', label: 'Where' }, { key: 'item', label: 'Item' },
        { key: 'avail', label: 'Plan', render: r => h('span', { text: r.avail === 'now' ? 'leave at ' + simClock(r.depart) : 'restock #' + r.k + ', leave ' + simClock(r.depart) }) },
        { key: 'land', label: 'Land', render: r => simClock(r.land) }, { key: 'units', label: 'Qty', render: r => r.units + ' (forecast ' + r.forecastQty + ')' },
        { key: 'full', label: 'Reality', sortVal: r => r.full, render: r => h('span', null, simBadge(r.full), h('span', { class: 'muted small', text: r.actualQty === null ? '' : ' ' + r.actualQty + ' there' })) },
        { key: 'restockErr', label: 'Restock error', sortVal: r => r.restockErr === null ? 9e9 : Math.abs(r.restockErr), render: r => r.restockErr === null ? '—' : (r.restockErr > 0 ? '+' : '') + Math.round(r.restockErr / 60) + ' min' }] }).el));
    } else {
      box.appendChild(h('div', { class: 'grid cols-4' },
        stat('Trips', String(s.trips), s.skipped ? s.skipped + ' skipped (still travelling)' : 'all followed'),
        stat('Trips with something in stock', simPct(s.tripsWithStock, s.trips), s.tripsWithStock + ' of ' + s.trips),
        stat('Items in stock on landing', simPct(s.inStock, s.itemChecks), s.inStock + ' of ' + s.itemChecks + ' checks'),
        stat('Sold out / uncertain / no data', s.soldOut + ' / ' + s.uncertain + ' / ' + s.noData, 'uncertain = changes within the margin of landing')));
      box.appendChild(h('div', { style: 'margin-top:12px' }, dataTable({ rows, defaultSort: 'ours', defaultDir: 'asc', pageSize: 10, empty: empty('No trip'), cols: [
        { key: 'country', label: 'Where', render: r => h('b', { text: r.country }) },
        { key: 'their', label: 'Their take-off', sortVal: r => r.their, render: r => r.their ? simClock(r.their) : '—' },
        { key: 'ours', label: 'Our take-off', render: r => simClock(r.ours) }, { key: 'landing', label: 'Our landing', render: r => r.landing ? simClock(r.landing) : '—' },
        { key: 'checks', label: 'Stock on landing', sort: false, render: r => r.skipped ? h('span', { class: 'muted', text: r.skipped }) : h('div', { class: 'chips' }, r.checks.map(c => h('span', { class: 'chip' }, c[0] + ' ', simBadge(c[1])))) },
        { key: 'ourReturn', label: 'Return', sortVal: r => r.ourReturn, render: r => r.ourReturn ? simClock(r.ourReturn) + (r.followed ? '' : ' (he did not return)') : '—' },
        { key: 'home', label: 'Back in Torn', render: r => r.home ? simClock(r.home) : '—' }] }).el));
    }
    if (run.result && run.result.truncated) box.appendChild(h('div', { class: 'note' }, 'The stock history of this period was too large and was cut: shorten the period for exact figures.'));
    return box;
  }

  async function simPage() {
    if (!(S.me && S.me.role === 'admin')) { view.appendChild(h('div', { class: 'card' }, empty('Access denied', 'This page is reserved for administrators.'))); return; }
    view.appendChild(head('Simulations', 'Replay the recorded stock and flights to see whether the planner (or following a player) would have found stock on landing.'));
    const now = Math.floor(Date.now() / 1000), body = h('div'); view.appendChild(body);
    const pl = await api('GET', '/admin/sim/players');
    const players = pl.ok ? pl.data.players : [];
    const kind = h('select', { 'aria-label': 'Simulation type' }, Object.keys(SIM_LABEL).map(k => h('option', { value: k, text: SIM_LABEL[k] })));
    const fromI = h('input', { type: 'datetime-local', value: simLocalInput(now - 24 * 3600), 'aria-label': 'From' }), toI = h('input', { type: 'datetime-local', value: simLocalInput(now), 'aria-label': 'To' });
    const plane = h('select', { 'aria-label': 'Aircraft' }, SIM_PLANES.map(a => h('option', { value: a[0], text: a[1] })));
    const num = (v, label, w) => h('input', { type: 'number', value: String(v), 'aria-label': label, title: label, style: 'width:' + (w || 90) + 'px' });
    const delayI = num(30, 'Delay after the player (s)'), marginI = num(30, 'Margin +- (s)'), freshI = num(10, 'Data freshness margin (s)'), topI = num(6, 'Items checked per trip'), needI = num(1, 'Quantity needed');
    const stepI = num(30, 'Step (minutes)'), carryI = num(27, 'Carry'), sellI = num(95, 'Sell at %'), bufI = num(60, 'Land after restock (s)');
    const playerS = h('select', { 'aria-label': 'Player' }, players.length ? players.map(p => h('option', { value: p.id, text: p.name + ' [' + p.id + '] · ' + p.flights + ' flights' + (p.company ? ' · ' + p.company : '') })) : [h('option', { value: '', text: 'No flight recorded yet' })]);
    const checksT = h('textarea', { rows: 4, placeholder: 'One flight per line:  Country; 2026-10-24 12:30:30; Airstrip\nJapan; 2026-10-24 13:00; Airstrip', style: 'width:100%;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:9px 11px;font:inherit' });
    const names = ['Mexico', 'Cayman Islands', 'Canada', 'Hawaii', 'United Kingdom', 'Argentina', 'Switzerland', 'Japan', 'China', 'United Arab Emirates', 'South Africa'];
    const cbs = names.map(n => h('label', { class: 'small', style: 'display:inline-flex;gap:4px;margin-right:10px' }, h('input', { type: 'checkbox', checked: true, value: n }), n));
    const lab = (t, el) => h('label', { class: 'field' }, t, el);
    const opts = h('div', { class: 'filters' });
    const msg = h('p', { class: 'muted small', role: 'status' });
    const queueBox = h('div'), resultsBox = h('div', { style: 'margin-top:20px' }), detailBox = h('div', { style: 'margin-top:12px' });

    function drawForm() {
      clear(opts); const k = kind.value;
      const fp = [lab('Type', kind)];
      if (k === 'follow') fp.push(lab('Player', playerS), lab('From', fromI), lab('To', toI), lab('Our aircraft', plane), lab('Delay after him (s)', delayI), lab('Margin ± (s)', marginI), lab('Data freshness (s)', freshI), lab('Items checked', topI), lab('Quantity needed', needI));
      if (k === 'check') fp.push(lab('Our aircraft (default)', plane), lab('Margin ± (s)', marginI), lab('Data freshness (s)', freshI), lab('Items checked', topI), lab('Quantity needed', needI), h('div', { style: 'flex-basis:100%' }, lab('Planned flights (local time)', checksT)));
      if (k === 'planner') fp.push(lab('From', fromI), lab('To', toI), lab('Every (min)', stepI), lab('Aircraft', plane), lab('Carry', carryI), lab('Sell at %', sellI), lab('Land after restock (s)', bufI), h('div', { style: 'flex-basis:100%' }, h('span', { class: 'small muted', text: 'Countries ' }), cbs));
      fp.forEach(x => opts.appendChild(x));
    }
    kind.addEventListener('change', drawForm);

    function currentJob() {
      const k = kind.value, t = (el) => Math.floor(new Date(el.value).getTime() / 1000), n = (el) => Number(el.value);
      const common = { plane: plane.value, margin: n(marginI), fresh: n(freshI), top: Math.max(1, Math.min(20, n(topI))), need: Math.max(1, n(needI)), delay: n(delayI) };
      if (k === 'follow') { if (!playerS.value) throw new Error('Choose a player.'); const p = Object.assign({ player: playerS.value, from: t(fromI), to: t(toI) }, common); if (!(p.from > 0 && p.to > p.from)) throw new Error('Check the period.'); return { kind: k, params: p, label: 'Follow ' + playerS.selectedOptions[0].text.split(' [')[0] + ' · ' + plane.value + ' · +' + p.delay + ' s' }; }
      if (k === 'check') { const flights = parseChecks(checksT.value); if (!flights.length) throw new Error('Add at least one planned flight (Country; date time; aircraft).'); return { kind: k, params: Object.assign({ flights }, common), label: flights.length + ' planned flight(s)' }; }
      const p = { from: t(fromI), to: t(toI), step: Math.max(5, n(stepI)), plane: plane.value, carry: n(carryI), sell: n(sellI), buffer: n(bufI), countries: cbs.map(l => l.querySelector('input')).filter(i => i.checked).map(i => i.value) };
      if (!(p.from > 0 && p.to > p.from)) throw new Error('Check the period.'); if ((p.to - p.from) / (p.step * 60) > 300) throw new Error('Too many steps (300 at most): raise the step or shorten the period.'); if (!p.countries.length) throw new Error('Choose a country.');
      return { kind: k, params: p, label: 'Planner ' + p.plane + ' · every ' + p.step + ' min' };
    }
    function drawQueue() {
      clear(queueBox);
      if (!SIM_QUEUE.length) { queueBox.appendChild(h('p', { class: 'muted small', text: 'Queue empty. Fill the form and press “Add to queue” (add as many as you want, then run them all).' })); return; }
      SIM_QUEUE.forEach((j, i) => queueBox.appendChild(h('div', { class: 'switch' }, h('span', null, h('b', { text: SIM_LABEL[j.kind] }), h('span', { class: 'muted small', text: ' ' + j.label })),
        h('span', { class: 'badge ' + (j.state === 'done' ? 'ok' : j.state === 'error' ? 'bad' : ''), text: j.state === 'error' ? j.status : j.state === 'run' ? j.status : j.state === 'done' ? 'done' : 'waiting' }),
        j.state === 'run' ? null : h('button', { class: 'ghost sm', onclick: () => { SIM_QUEUE.splice(i, 1); drawQueue(); } }, 'Remove'))));
    }
    let running = false;
    async function runAll() {
      if (running) return; running = true;
      for (const j of SIM_QUEUE.filter(x => x.state !== 'done')) {
        j.state = 'run'; j.status = '…'; drawQueue();
        try { const res = await simExecute(j, (t) => { j.status = t; drawQueue(); }); j.state = 'done'; j.runId = res.id; }
        catch (e) { j.state = 'error'; j.status = String(e.message || e).slice(0, 80); }
        drawQueue();
      }
      running = false; await drawResults();
    }
    async function drawResults() {
      const r = await api('GET', '/admin/sim/runs'); clear(resultsBox);
      resultsBox.appendChild(h('h3', { text: 'Saved simulations' }));
      const runs = r.ok ? r.data.runs : [];
      if (!runs.length) { resultsBox.appendChild(h('p', { class: 'muted small', text: 'Nothing yet.' })); return; }
      resultsBox.appendChild(dataTable({ rows: runs, defaultSort: 'createdAt', defaultDir: 'desc', pageSize: 10, empty: empty('Nothing yet'), cols: [
        { key: 'createdAt', label: 'Run', render: x => dFmt(x.createdAt) }, { key: 'kind', label: 'Type', render: x => SIM_LABEL[x.kind] || x.kind },
        { key: 'label', label: 'Settings', render: x => h('span', { class: 'muted', text: x.label || '' }) },
        { key: 'summary', label: 'Result', sort: false, render: x => { const s = x.summary || {}; return h('span', { text: x.kind === 'planner' ? 'stock there ' + simPct(s.hit, s.judged) + ' · ' + s.decisions + ' decisions' : 'in stock ' + simPct(s.inStock, s.itemChecks) + ' · ' + s.trips + ' trips' }); } },
        { key: 'id', label: '', sort: false, render: x => h('div', { class: 'row' }, h('button', { class: 'ghost sm', onclick: async (ev) => { ev.stopPropagation(); const d = await api('GET', '/admin/sim/runs?id=' + x.id); clear(detailBox); if (d.ok) { detailBox.appendChild(h('h3', { text: (SIM_LABEL[x.kind] || x.kind) + ' · ' + (x.label || '') })); detailBox.appendChild(simResultView(d.data.run)); detailBox.scrollIntoView({ behavior: 'smooth' }); } } }, 'Open'),
          h('button', { class: 'danger sm', onclick: async (ev) => { ev.stopPropagation(); if (!confirm('Delete this simulation?')) return; await api('POST', '/admin/sim/runs', { delete: x.id }); clear(detailBox); drawResults(); } }, 'Delete')) }] }).el);
    }
    body.appendChild(h('div', { class: 'card' }, h('h2', { text: 'New simulation' }),
      h('p', { class: 'muted small', text: 'Follow a player: we take off a few seconds after him on the same route, check the recorded stock on landing (± margin; a stock change inside the margin is reported as uncertain, a country without any recorded change around landing as “no data”), and come back when he does. If he flies again we follow him again. Planner accuracy: at each step the planner decides with only what was known then, and the result is compared with what the stock really was on landing.' }),
      opts,
      h('div', { class: 'row' }, h('button', { onclick: () => { try { SIM_QUEUE.push(Object.assign(currentJob(), { state: 'wait' })); msg.textContent = ''; drawQueue(); } catch (e) { msg.textContent = e.message; } } }, 'Add to queue'),
        h('button', { class: 'ghost', onclick: runAll }, 'Run the queue'), h('button', { class: 'ghost', onclick: () => { for (let i = SIM_QUEUE.length - 1; i >= 0; i--) if (SIM_QUEUE[i].state !== 'run') SIM_QUEUE.splice(i, 1); drawQueue(); } }, 'Clear')), msg));
    body.appendChild(h('div', { class: 'card', style: 'margin-top:16px' }, h('h2', { text: 'Queue' }), queueBox));
    body.appendChild(resultsBox); body.appendChild(detailBox);
    drawForm(); drawQueue(); await drawResults();
  }
/*PSIM-END*/
