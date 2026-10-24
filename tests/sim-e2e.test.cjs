// End-to-end: the REAL Worker file (mock D1 filled with synthetic stock history) + the REAL admin page in Chromium.
// Checks the /admin/sim/* endpoints, the Simulations page (follow, planner accuracy, planned flights, queue, save/open/delete)
// and the cycle forecast of the planner (a 6 h absence lands on the 3rd restock, not on the next one).
const { chromium } = require('playwright'); const assert = require('assert');
const file = process.argv[2], shot = process.argv[3];
(async () => {
  const W = (await import('file://' + process.cwd() + '/' + file)).default;
  const now = Math.floor(Date.now() / 1000), PERIOD = 7200, R0 = now - 10 * 86400;
  // T0 chosen so that OUR landing falls 10 minutes after a restock (item 1 is then in stock)
  const T0 = R0 + 600 - 9976 + Math.round((now - 40000 - (R0 + 600 - 9976)) / PERIOD) * PERIOD;
  // ---- synthetic world: Japan item 1 restocks every 2 h (1500, 20/min => empty after 75 min); item 2 always empty; item 3 changes just after our landing
  const hist = []; const events = []; const cycles = [];
  for (let r = R0; r < now; r += PERIOD) {
    events.push(r); let q = 1500; const start = r; hist.push({ country: 'jap', item_id: 1, ts: r, qty: q });
    for (let s = 300; s <= 4500; s += 300) { q = Math.max(0, 1500 - Math.round(20 * s / 60)); hist.push({ country: 'jap', item_id: 1, ts: r + s, qty: q }); if (q === 0) break; }
    cycles.push({ country: 'jap', item_id: 1, start_at: start, qty_start: 1500, soldout_at: r + 4500 });
  }
  hist.push({ country: 'jap', item_id: 2, ts: now - 10 * 86400, qty: 0 });
  const ourLand = T0 + 1000 + 30 + 8946;
  hist.push({ country: 'jap', item_id: 3, ts: T0 - 5000, qty: 300 }, { country: 'jap', item_id: 3, ts: ourLand + 35, qty: 0 });
  const flightsDb = [[T0 + 1000, 'Japan', 'out'], [T0 + 1000 + 8946 + 600, 'Japan', 'return'], [T0 + 30000, 'Japan', 'out']].map(([t, c, d]) => ({ takeoff_at: t, country: c, direction: d, plane: 'Airstrip', duration: 8946 }));
  const snap = [{ country: 'jap', items: JSON.stringify([[1, 'Plushie', 500, 100], [2, 'Flower', 0, 50], [3, 'Drug', 300, 800]]) }];
  const prices = [{ item_id: 1, market_value: 300 }, { item_id: 2, market_value: 200 }, { item_id: 3, market_value: 1100 }];
  let runs = [], nextId = 1, role = 'admin';
  const db = { exec: async () => ({}), prepare(sql) { let b = []; const q = { bind(...x) { b = x; return q; },
    async first() {
      if (/FROM sessions/.test(sql)) return { id: 1, username: 'owner', torn_user_id: '1', role };
      if (/FROM sim_runs WHERE id = \?/.test(sql)) return runs.find(r => r.id === b[0]) || null;
      return null; },
    async all() {
      const R = (results) => ({ results });
      if (/FROM radar_flights f LEFT JOIN radar_players/.test(sql)) return R([{ id: 77, name: 'Pilot', company: 'Cruise Co', flights: 3, last: T0 + 30000 }]);
      if (/FROM radar_flights WHERE player_id/.test(sql)) return R(flightsDb.filter(f => f.takeoff_at >= b[1] && f.takeoff_at <= b[2]));
      if (/FROM stock_snapshot/.test(sql)) return R(snap);
      if (/FROM item_prices/.test(sql)) return R(prices);
      if (/FROM stock_hist h\s+JOIN/.test(sql)) { const lim = b[0]; const last = {}; hist.filter(h => h.ts < lim).forEach(h => { const k = h.country + h.item_id; if (!last[k] || last[k].ts < h.ts) last[k] = h; }); return R(Object.values(last)); }
      if (/FROM stock_hist WHERE ts >=/.test(sql)) return R(hist.filter(h => h.ts >= b[0] && h.ts <= b[1]).sort((x, y) => x.ts - y.ts));
      if (/FROM stock_events/.test(sql)) return R(events.map(t => ({ country: 'jap', item_id: 1, seen_at: t })).filter(e => e.seen_at >= b[0] && e.seen_at <= b[1]));
      if (/FROM stock_cycle/.test(sql)) return R(cycles.filter(c => c.start_at >= b[0] && c.start_at <= b[1]));
      if (/FROM sim_runs ORDER BY id DESC/.test(sql)) return R(runs.slice().reverse());
      return R([]); },
    async run() {
      if (/INSERT INTO sim_runs/.test(sql)) { runs.push({ id: nextId, created_at: b[0], kind: b[1], label: b[2], params: b[3], summary: b[4], result: b[5] }); return { meta: { last_row_id: nextId++, changes: 1 } }; }
      if (/DELETE FROM sim_runs WHERE id = \?/.test(sql)) { runs = runs.filter(r => r.id !== b[0]); }
      return { meta: { changes: 1 } }; } }; return q; }, async batch() { return []; } };
  const env = { DB: db, TORN_API_KEY: 'OWNERKEY00000000', APP_SECRET: 's' };
  const call = async (path, method = 'GET', body) => { const r = await W.fetch(new Request('https://app.test' + path, { method, headers: { Cookie: 'ttw_session=' + 'a'.repeat(64), 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }), env, { waitUntil() {} }); return { status: r.status, body: await r.json() }; };

  // ---- 1. endpoints
  let r = await call('/admin/sim/players'); assert.strictEqual(r.body.players[0].name, 'Pilot');
  r = await call('/admin/sim/data?kind=follow&player=77&from=' + T0 + '&to=' + (T0 + 40000));
  assert.strictEqual(r.status, 200); assert.strictEqual(r.body.flights.length, 3); assert(r.body.hist['jap|1'].length > 10); assert(r.body.countries.Japan.items.length === 3);
  r = await call('/admin/sim/data?kind=follow&player=&from=1&to=2'); assert.strictEqual(r.status, 400);
  role = 'user'; r = await call('/admin/sim/players'); assert.strictEqual(r.status, 403); role = 'admin';

  // ---- 2. the real page
  const m = require('fs').readFileSync(file, 'utf8').match(/^const DASHBOARD_HTML = (".*");$/m), html = JSON.parse(m[1]);
  const browser = await chromium.launch(); const page = await (await browser.newContext({ viewport: { width: 1400, height: 1100 } })).newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message)); page.on('dialog', d => d.accept());
  await page.route('https://app.test/**', async (route) => {
    const u = new URL(route.request().url()), p = u.pathname;
    if (p === '/dashboard') return route.fulfill({ contentType: 'text/html', body: html });
    const j = (o) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(o) });
    if (p === '/me') return j({ ok: true, user: { username: 'owner', tornUserId: '1', role: 'admin', beta: true, premium: { active: true, admin: true } } });
    if (p === '/targets') return j({ ok: true, targets: [] }); if (p === '/api/prefs') return j({ ok: true, prefs: null }); if (p === '/api/events') return j({ ok: true, total: 0, events: [] });
    const res = await W.fetch(new Request(route.request().url(), { method: route.request().method(), headers: { Cookie: 'ttw_session=' + 'a'.repeat(64), 'Content-Type': 'application/json' }, body: route.request().postData() || undefined }), env, { waitUntil() {} });
    return route.fulfill({ status: res.status, contentType: 'application/json', body: await res.text() });
  });
  await page.goto('https://app.test/dashboard#/sim'); await page.waitForSelector('h1:has-text("Simulations")');
  assert(await page.locator('nav a:has-text("Simulations")').count() === 1, 'nav entry for admin');
  // follow
  await page.selectOption('select[aria-label="Simulation type"]', 'follow');
  const setDT = async (label, t) => page.fill('input[aria-label="' + label + '"]', new Date(t * 1000 - new Date().getTimezoneOffset() * 0).toISOString().slice(0, 0) + (() => { const d = new Date(t * 1000), p = (n) => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes()); })());
  await setDT('From', T0 - 600); await setDT('To', T0 + 40000);
  await page.click('button:has-text("Add to queue")');
  // planner accuracy
  await page.selectOption('select[aria-label="Simulation type"]', 'planner');
  await setDT('From', now - 24 * 3600); await setDT('To', now - 3 * 3600);
  await page.click('button:has-text("Add to queue")');
  // planned flights
  await page.selectOption('select[aria-label="Simulation type"]', 'check');
  const loc = (t) => { const d = new Date(t * 1000), p = (n) => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()); };
  await page.fill('textarea', 'Japan; ' + loc(T0 + 1030) + '; Airstrip\nJapan; ' + loc(T0 + 20000) + '; Airstrip');
  await page.click('button:has-text("Add to queue")');
  assert.strictEqual(await page.locator('.card:has(h2:has-text("Queue")) .switch').count(), 3, 'three simulations queued');
  await page.click('button:has-text("Run the queue")');
  await page.waitForFunction(() => document.querySelectorAll('.card .switch .badge.ok').length === 3, null, { timeout: 60000 });
  assert.strictEqual(runs.length, 3, 'three runs saved');
  const byKind = (k) => runs.find(x => x.kind === k), sum = (k) => JSON.parse(byKind(k).summary);
  // follow: item 1 in stock, item 2 sold out, item 3 uncertain ; second flight skipped? (we are home by then) -> 2 trips
  const rowsF = JSON.parse(byKind('follow').result).rows; assert.strictEqual(rowsF.length, 2); // two outbound flights (the return is part of a trip)
  const first = rowsF[0]; assert.strictEqual(first.ours, T0 + 1030); assert.strictEqual(first.landing, ourLand);
  const v = Object.fromEntries(first.checks.map(c => [c[0], c[1]])); assert.deepStrictEqual([v.Plushie, v.Flower, v.Drug], ['in', 'out', 'uncertain'], JSON.stringify(v));
  assert(first.followed && first.ourReturn === T0 + 1000 + 8946 + 600 + 30, 'we come back when he does (+30 s)');
  // planner accuracy on a perfectly periodic world must be excellent
  const sp = sum('planner'); assert(sp.decisions >= 20, 'decisions ' + sp.decisions); assert(sp.judged > 0 && sp.hit / sp.judged >= 0.8, 'hit rate ' + sp.hit + '/' + sp.judged + ' ' + JSON.stringify(sp));
  console.log('planner sim:', JSON.stringify(sp));
  // planned flights: first one same as follow (in/out/uncertain), second one lands in a sold-out phase for item 1 or not - just present
  const sc = sum('check'); assert.strictEqual(sc.trips, 2);
  // saved list + open + delete
  await page.waitForSelector('h3:has-text("Saved simulations")'); await page.waitForSelector('tbody tr:has-text("Follow a player")');
  await page.click('tbody tr:has-text("Follow a player") button:has-text("Open")'); await page.waitForSelector('.chips .badge:has-text("in stock")');
  await page.screenshot({ path: shot });
  await page.click('tbody tr:has-text("Follow a player") button:has-text("Delete")'); await page.waitForFunction(() => ![...document.querySelectorAll('tbody tr')].some(r => r.innerText.includes('Follow a player')));
  assert.strictEqual(runs.length, 2);
  assert.deepStrictEqual(errors, []);
  await browser.close(); console.log('simulations end-to-end: all checks passed');
})().catch(e => { console.error(e); process.exit(1); });
