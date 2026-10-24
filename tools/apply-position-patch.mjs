// Builds the upgraded Worker from an original TornScope Worker file:
//   node tools/apply-position-patch.mjs <in.mjs> <out.mjs>
// 1. planner uses "my position" (+30 s after landing)            2. restock forecast by CYCLES (TSIM engine)
// 3. GET /api/me/travel                                          4. admin "Simulations" page + /admin/sim/* endpoints
// Exact-anchor replacements only (each anchor must match exactly once); everything else stays byte for byte.
import fs from 'fs';
const [inp, out] = process.argv.slice(2);
const read = (f) => fs.readFileSync(new URL('../site-modules/' + f, import.meta.url), 'utf8');
const between = (text, a, b) => { const i = text.indexOf(a), j = text.indexOf(b); if (i < 0 || j < 0) throw new Error('markers ' + a); return text.slice(i, j + b.length); };
let src = fs.readFileSync(inp, 'utf8');

function rep(text, a, b, label) {
  const n = text.split(a).length - 1;
  if (n !== 1) throw new Error('anchor "' + label + '" found ' + n + ' times (expected 1)');
  return text.replace(a, () => b);
}
function replaceBlock(text, startA, endA, b, label, mustContain) {
  const i = text.indexOf(startA), j = text.indexOf(endA);
  if (text.split(startA).length !== 2 || text.split(endA).length !== 2 || i < 0 || j < i) throw new Error('block anchors "' + label + '"');
  const old = text.slice(i, j);
  (mustContain || []).forEach(k => { if (!old.includes(k)) throw new Error('block "' + label + '" is not the expected code (missing ' + k + ')'); });
  return text.slice(0, i) + b + text.slice(j);
}

/* ================= Worker ================= */
const TRAVEL_FN = `
// ---- Player's own position for the planner ("Use my position"). Uses the stored personal key; the key is never returned.
// Torn "travel": { destination, timestamp, departed, time_left }.
function travelToPos(data, now) {
  const t = data && typeof data.travel === "object" && data.travel ? data.travel : null;
  if (!t) return null;
  const dest = String(t.destination || "");
  const left = Math.max(0, Math.floor(Number(t.time_left) || 0));
  const home = /^torn$/i.test(dest.trim());
  const country = home ? null : findTravelCountry(dest);
  if (left > 0) {
    if (home) return { state: "flying", direction: "return", country: null, landAt: now + left };
    return country ? { state: "flying", direction: "out", country, landAt: now + left } : null;
  }
  if (!home && country) return { state: "abroad", country, landAt: 0 };
  return { state: "torn", country: null, landAt: 0 };
}
`;
const sim = read('sim-worker.js');
src = rep(src, 'let schemaReady = false;', between(sim, '/*WSIM-SCHEMA-BEGIN*/', '/*WSIM-SCHEMA-END*/') + '\n\nlet schemaReady = false;', 'schemaReady');
src = rep(src, 'const TS_WORKER = {', TRAVEL_FN + '\n' + between(sim, '/*WSIM-BEGIN*/', '/*WSIM-END*/') + '\n\nconst TS_WORKER = {', 'TS_WORKER');

const ROUTES = `    if (path === "/api/me/travel" && request.method === "GET") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      try {
        if (!vaultAvailable(env)) return json({ ok: false, message: "Key storage is not configured on the server." }, 503);
        const row = await env.DB.prepare("SELECT enc, status FROM user_keys WHERE account_id = ?").bind(account.id).first();
        if (!row || row.status !== "valid") return json({ ok: false, needKey: true, message: "Save your Torn API key on the Premium page to use this, or enter your position by hand." }, 404);
        const bucket = "mytravel:" + account.id;
        const wait = await lockedSeconds(env, bucket);
        if (wait > 0) return tooManyAttempts(wait);
        await registerFailure(env, bucket, 1, 10, 10);   // at most one read every 10 seconds
        let apiKey;
        try { apiKey = await decryptUserKey(env, account.id, row.enc); }
        catch { return json({ ok: false, message: "The stored key cannot be read. Save it again on the Premium page." }, 500); }
        const res = await tornKeyRequest("user/", "travel", apiKey);
        if (!res.data) return json({ ok: false, message: "Could not reach the Torn API." }, 502);
        if (res.data.error) return json({ ok: false, message: tornKeyErrorMessage(res.data.error.code) }, 400);
        const now = nowSeconds();
        const pos = travelToPos(res.data, now);
        if (!pos) return json({ ok: false, message: "Torn returned a position we do not recognise." }, 502);
        return json({ ok: true, now, pos });
      } catch (error) {
        console.error("My travel error:", error?.name || "error");
        return json({ ok: false, message: "Could not read your position" }, 500);
      }
    }

    if (path.startsWith("/admin/sim/")) {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!requireAdmin(account)) return json({ ok: false, message: "Access denied" }, 403);
      try { return await simApi(request, env, url, path); }
      catch (error) { console.error("Simulation error:", error?.stack || String(error)); return json({ ok: false, message: "Simulation data failed" }, 500); }
    }

`;
src = rep(src, '    if (path === "/api/radar/stock" && request.method === "GET") {', ROUTES + '    if (path === "/api/radar/stock" && request.method === "GET") {', 'routes');

/* ================= Dashboard page ================= */
const m = src.match(/^const DASHBOARD_HTML = (".*");$/m);
if (!m) throw new Error('DASHBOARD_HTML line not found');
let h = JSON.parse(m[1]);

const NEW_PLAN = `  // ---- Player position: the first flight can only start after the current one has landed (+ MY_DELAY s to open the travel page)
  const MY_DELAY = 30;
  const MY_POS_OFF = { state: 'torn' };
  const myPos = () => RADAR_PLAN.pos && RADAR_PLAN.pos.state ? RADAR_PLAN.pos : MY_POS_OFF;
  function earliestDeparture(pos, now, dur) {
    if (!pos || pos.state === 'torn') return { at: now, why: '' };
    const ready = Math.max(now, (pos.landAt || 0) + MY_DELAY);
    if (pos.state === 'flying' && pos.direction === 'return') return { at: ready, why: 'You land in Torn, earliest take-off ' };
    const back = dur(pos.country) || 0;
    if (pos.state === 'flying') return { at: ready + back, why: 'You land in ' + pos.country + ' then must fly back. Earliest take-off from Torn ' };
    return { at: now + MY_DELAY + back, why: 'You are in ' + pos.country + ': fly back first. Earliest take-off from Torn ' };
  }
  // One row per country/item with what a trip would earn if I leave at \`start\` (>= now). All times are unix seconds.
  // The stock on landing is FORECAST with the restock cycles (TSIM): if I land in 6 h, it is the 3rd restock after now that counts, not the next one.
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
        const rate = i.depletionNow > 0 ? i.depletionNow : (i.depletionMed || 0);
        const d = TSIM.decide(i, P, now, start, dur);
        const leaveAt = d.avail === 'restock' ? d.departAt : (i.nextRestockAt > 0 ? i.nextRestockAt + P.buffer - dur : 0);
        const perHour = pu > 0 && d.units > 0 ? Math.round(d.units * pu / (2 * dur / 3600)) : 0;
        out.push(Object.assign({}, i, { country: c.name, code: c.code, key: c.code + '|' + i.id, dur, pu, avail: d.avail, units: d.units, departAt: d.departAt, leaveAt, perHour, qtyLand: d.qtyLand, rate, tripProfit: pu > 0 ? d.units * pu : 0, fcK: d.k, fcConf: d.conf, fcRestockAt: d.restockAt }));
      });
    });
    return out;
  }
  // Greedy day plan: always take the trip that earns the most per hour of elapsed time (waiting included). Every candidate is
  // re-forecast for the moment I could really leave (t): after a trip I am back + MY_DELAY s later, and the stock has moved on.
  function dayPlan(rows, P, now, start) {
    start = Math.max(now, start || now);
    const end = now + P.horizon * 3600, used = {}, trips = [];
    let t = start;
    while (trips.length < 14) {
      let best = null;
      rows.forEach(r => {
        if (used[r.key] || !(r.pu > 0)) return;
        const d = TSIM.decide(r, P, now, t, r.dur); if (d.units <= 0) return;
        const depart = d.departAt, back = depart + 2 * r.dur; if (back > end) return;
        const score = d.units * r.pu / (back - t);
        if (!best || score > best.score) best = { r: Object.assign({}, r, { avail: d.avail, units: d.units, fcK: d.k, fcConf: d.conf, fcRestockAt: d.restockAt }), depart, land: depart + r.dur, back, score };
      });
      if (!best) break;
      trips.push(best); used[best.r.key] = true; t = best.back + MY_DELAY;
    }
    return { trips, total: trips.reduce((a, x) => a + x.r.units * x.r.pu, 0) };
  }
`;
h = replaceBlock(h, '  // One row per country/item with what a trip would earn. now = unix seconds.\n  function planRows(', '  const compact = (n, money) =>', NEW_PLAN, 'planner block', ['const soldBy', 'function dayPlan']);
// the engine itself (same source as the Worker tests)
const engine = between(read('sim-engine.js'), '/*ENGINE-BEGIN*/', '/*ENGINE-END*/');
h = rep(h, '  // ---- Player position: the first flight', engine + '\n  // ---- Player position: the first flight', 'engine');

h = rep(h, "const P = RADAR_PLAN; let rows = planRows(ST, P, stNow());", "const P = RADAR_PLAN; let rows = planRows(ST, P, stNow(), firstDeparture().at);", 'filtered');
h = rep(h, "const plan = dayPlan(rows, PL, now);", "const plan = dayPlan(rows, PL, now, firstDeparture().at);", 'plan call');
h = rep(h, "clock(r.nextRestockAt)", "clock(r.fcRestockAt || r.nextRestockAt)", 'detail restock');
h = rep(h, "clock(t.r.nextRestockAt)", "clock(t.r.fcRestockAt || t.r.nextRestockAt) + (t.r.fcK > 1 ? ' (cycle ' + t.r.fcK + ', forecast)' : '')", 'plan restock');

h = replaceBlock(h, "      function takeoffCell(r) {", "      function itemDetail(r) {", `      function takeoffCell(r) {
        const now = stNow();
        const cyc = r.fcK > 0 ? h('span', { class: 'muted small', title: 'Forecast: restocks come about every ' + cad(r.cadenceMin) + ' (confidence ' + Math.round((r.fcConf || 0) * 100) + '%)', text: ' · restock #' + r.fcK + ' ' + clockHM(r.fcRestockAt) + ' est.' }) : null;
        if (r.avail === 'now') return h('span', null, r.departAt > now + 5 ? h('b', { text: clock(r.departAt) }) : h('b', { class: 'ok-text', text: 'Now' }), h('span', { class: 'muted small', text: (r.departAt > now + 5 ? inTxt(r.departAt, now) : '') + (r.qtyLand > 0 ? ' · ~' + r.qtyLand.toLocaleString('en-US') + ' left on landing' : '') }), cyc);
        if (r.avail === 'restock') return h('span', null, h('b', { text: clock(r.departAt) }), h('span', { class: 'muted small', text: r.departAt > now ? inTxt(r.departAt, now) : ' leave now' }), cyc);
        if (r.avail === 'late') return h('span', { class: 'bad-text', text: 'Sold out by arrival' });
        return h('span', { class: 'muted', text: 'no forecast yet' });
      }
`, 'takeoffCell', ["r.avail === 'restock'", "'Sold out by arrival'"]);

h = rep(h, "      function planSide() {", `      const firstDeparture = () => earliestDeparture(myPos(), stNow(), (c) => (ST && ST.travelSec && ST.travelSec[c] && ST.travelSec[c][RADAR_PLAN.type]) || 0);
      // "My position" panel: read it from Torn (stored key) or type it. Times are entered in the clock chosen above (TCT / local).
      function posPanel() {
        const P = RADAR_PLAN, pos = myPos(), msg = h('div', { class: 'small muted', role: 'status' });
        const names = PLAN_GROUPS.flatMap(g => g[1]);
        const kind = pos.state === 'flying' ? (pos.direction === 'return' ? 'home' : 'out') : pos.state;
        const parse = (txt) => { const m = /^(\\d{1,2}):(\\d{2})(?::(\\d{2}))?$/.exec(String(txt).trim()); if (!m) return 0; const d = new Date(stNow() * 1000), u = P.tz === 'utc'; let t = (u ? Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), +m[1], +m[2], +(m[3] || 0)) : new Date(d.getFullYear(), d.getMonth(), d.getDate(), +m[1], +m[2], +(m[3] || 0)).getTime()) / 1000; if (t < stNow() - 3600) t += 86400; return Math.floor(t); };
        const save = (next) => { P.pos = next; savePlan(); redrawStock(); };
        const sel = h('select', { 'aria-label': 'My position', onchange: (e) => { const v = e.target.value; save(v === 'torn' ? { state: 'torn' } : v === 'home' ? { state: 'flying', direction: 'return', landAt: 0 } : v === 'out' ? { state: 'flying', direction: 'out', country: pos.country || 'Mexico', landAt: 0 } : { state: 'abroad', country: pos.country || 'Mexico' }); } },
          [['torn', 'In Torn'], ['home', 'Flying home'], ['out', 'Flying out'], ['abroad', 'Abroad (landed)']].map(o => h('option', { value: o[0], selected: o[0] === kind }, o[1])));
        const country = (kind === 'out' || kind === 'abroad') ? h('select', { 'aria-label': 'Country', onchange: (e) => save(Object.assign({}, pos, { country: e.target.value })) }, names.map(n => h('option', { value: n, selected: n === pos.country }, n))) : null;
        const land = pos.state === 'flying' ? h('input', { type: 'text', placeholder: 'Lands at HH:MM:SS', value: pos.landAt ? clock(pos.landAt) : '', 'aria-label': 'Landing time', onchange: (e) => { const t = parse(e.target.value); if (!t) { msg.textContent = 'Use HH:MM or HH:MM:SS.'; return; } save(Object.assign({}, pos, { landAt: t })); } }) : null;
        const auto = h('button', { class: 'ghost sm', type: 'button', onclick: async (ev) => {
          ev.currentTarget.disabled = true; msg.textContent = 'Reading your position…';
          const r = await api('GET', '/api/me/travel');
          if (r.ok && r.data.pos) save(r.data.pos); else { msg.textContent = r.data.message || 'Could not read your position.'; ev.currentTarget.disabled = false; }
        } }, 'Use my position');
        return h('div', { class: 'sec' }, h('div', { class: 'small muted', text: 'My position' }), sel, country, land, h('div', { class: 'row' }, auto), msg);
      }
      function planSide() {`, 'planSide');
h = rep(h, "          h('div', { class: 'small muted sec', text: 'Countries' }),", "          posPanel(),\n          h('div', { class: 'small muted sec', text: 'Countries' }),", 'planSide Countries');
h = rep(h, "        // best routes: the best item of each country, three best countries", "        { const fd = firstDeparture(); if (fd.at > now + 1) main.appendChild(h('div', { class: 'note info' }, h('b', { text: 'My position. ' }), fd.why + clock(fd.at) + inTxt(fd.at, now) + '. Take-off times below start from then (' + MY_DELAY + ' s minimum after landing).')); }\n        // best routes: the best item of each country, three best countries", 'banner');

// admin Simulations page
h = rep(h, "  /* ================= PAGE: admin ================= */", between(read('sim-page.js'), '/*PSIM-BEGIN*/', '/*PSIM-END*/') + "\n  /* ================= PAGE: admin ================= */", 'sim page');
h = rep(h, "['admin', '🛡', 'Admin']", "['admin', '🛡', 'Admin'], ['sim', '🧪', 'Simulations']", 'PAGES');
h = rep(h, "      if (id === 'admin' && !(S.me && S.me.role === 'admin')) return;", "      if ((id === 'admin' || id === 'sim') && !(S.me && S.me.role === 'admin')) return;", 'renderNav');
h = rep(h, "radar: radarPage, war: warPage, premium: premiumPage, settings, admin }", "radar: radarPage, war: warPage, premium: premiumPage, settings, admin, sim: simPage }", 'route map');

src = src.replace(m[0], () => 'const DASHBOARD_HTML = ' + JSON.stringify(h).replace(/<\//g, '<\\/') + ';');
fs.writeFileSync(out, src);
console.log('ok', out);
