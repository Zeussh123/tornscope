// Applies "planner uses my position" to a TornScope Worker file: node tools/apply-position-patch.mjs <in.mjs> <out.mjs>
// Exact-anchor replacements only (each anchor must match exactly once); the rest of the file is left byte for byte as it was.
import fs from 'fs';
const [inp, out] = process.argv.slice(2);
let src = fs.readFileSync(inp, 'utf8');

function rep(text, a, b, label) {
  const n = text.split(a).length - 1;
  if (n !== 1) throw new Error('anchor "' + label + '" found ' + n + ' times (expected 1)');
  return text.replace(a, () => b);
}

/* ---------------- 1. Worker: GET /api/me/travel ---------------- */
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
src = rep(src, 'const TS_WORKER = {', TRAVEL_FN + '\nconst TS_WORKER = {', 'TS_WORKER');

const ROUTE = `    if (path === "/api/me/travel" && request.method === "GET") {
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

`;
src = rep(src, '    if (path === "/api/radar/stock" && request.method === "GET") {', ROUTE + '    if (path === "/api/radar/stock" && request.method === "GET") {', 'route');

/* ---------------- 2. Dashboard page (decoded, edited, re-encoded) ---------------- */
const m = src.match(/^const DASHBOARD_HTML = (".*");$/m);
if (!m) throw new Error('DASHBOARD_HTML line not found');
let h = JSON.parse(m[1]);

// planRows: leave at `start`
h = rep(h, 'function planRows(ST, P, now) {\n    const out = [], q = String(P.q || \'\').trim().toLowerCase();',
  'function planRows(ST, P, now, start) {\n    const out = [], q = String(P.q || \'\').trim().toLowerCase();\n    start = Math.max(now, start || now);', 'planRows head');
h = rep(h, '        const land = now + dur;\n        const qtyLand = i.qty > 0 ? (rate > 0 ? Math.max(0, Math.floor(i.qty - rate * dur / 60)) : i.qty) : 0;',
  '        const land = start + dur;\n        const qtyLand = i.qty > 0 ? (rate > 0 ? Math.max(0, Math.floor(i.qty - rate * (land - now) / 60)) : i.qty) : 0;', 'planRows land');
h = rep(h, "units = Math.min(P.carry, afford, qtyLand); departAt = now; }\n        else if (i.nextRestockAt > 0) { avail = 'restock'; units = Math.min(P.carry, afford, i.restockQty > 0 ? i.restockQty : P.carry); departAt = Math.max(now, leaveAt); }",
  "units = Math.min(P.carry, afford, qtyLand); departAt = start; }\n        else if (i.nextRestockAt > 0) {\n          departAt = Math.max(start, leaveAt);\n          const stockAtLand = i.restockQty > 0 ? i.restockQty - (rate > 0 ? rate * Math.max(0, departAt + dur - i.nextRestockAt) / 60 : 0) : P.carry;\n          avail = stockAtLand > 0 ? 'restock' : 'late';\n          units = avail === 'restock' ? Math.min(P.carry, afford, Math.floor(stockAtLand)) : 0;\n        }", 'planRows avail');

// dayPlan: first trip not before `start`, 30 s after each return
h = rep(h, 'function dayPlan(rows, P, now) {\n    const end = now + P.horizon * 3600, used = {}, trips = [];\n    let t = now;',
  'function dayPlan(rows, P, now, start) {\n    start = Math.max(now, start || now);\n    const end = now + P.horizon * 3600, used = {}, trips = [];\n    let t = start;', 'dayPlan head');
h = rep(h, "if (t > now + 60 && !(r.emptiesAt > 0 && t + r.dur < r.emptiesAt)) return; depart = t; }", "if (t > start + 60 && !(r.emptiesAt > 0 && t + r.dur < r.emptiesAt)) return; depart = t; }", 'dayPlan now');
h = rep(h, 'trips.push(best); used[best.r.key] = true; t = best.back;', 'trips.push(best); used[best.r.key] = true; t = best.back + MY_DELAY;', 'dayPlan back');

// position helpers (after fmtDur)
const HELPERS = `
  // ---- Player position: the first flight can only start after the current one has landed (+ MY_DELAY s to open the travel page)
  const MY_DELAY = 30;
  const MY_POS_OFF = { state: 'torn' };
  const myPos = () => RADAR_PLAN.pos && RADAR_PLAN.pos.state ? RADAR_PLAN.pos : MY_POS_OFF;
  function earliestDeparture(pos, now, dur) {
    if (!pos || pos.state === 'torn') return { at: now, why: '' };
    const ready = Math.max(now, (pos.landAt || 0) + MY_DELAY);
    if (pos.state === 'flying' && pos.direction === 'return') return { at: ready, why: 'You land in Torn at ' };
    const back = dur(pos.country) || 0;
    if (pos.state === 'flying') return { at: ready + back, why: 'You land in ' + pos.country + ' then must fly back. Earliest take-off from Torn ' };
    return { at: now + MY_DELAY + back, why: 'You are in ' + pos.country + ': fly back first. Earliest take-off from Torn ' };
  }
`;
h = rep(h, "  // One row per country/item with what a trip would earn. now = unix seconds.", HELPERS + "  // One row per country/item with what a trip would earn. now = unix seconds.", 'helpers');

// first departure used by the list and the plan
h = rep(h, "const P = RADAR_PLAN; let rows = planRows(ST, P, stNow());", "const P = RADAR_PLAN; let rows = planRows(ST, P, stNow(), firstDeparture().at);", 'filtered');
h = rep(h, "const plan = dayPlan(rows, PL, now);", "const plan = dayPlan(rows, PL, now, firstDeparture().at);", 'plan call');
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

// take-off cell: "Now" becomes a clock time when I cannot leave yet
h = rep(h, "        const now = stNow();\n        if (r.avail === 'now') return", "        const now = stNow();\n        if (r.avail === 'now' && r.departAt > now + 5) return h('span', null, h('b', { text: clock(r.departAt) }), h('span', { class: 'muted small', text: inTxt(r.departAt, now) + (r.qtyLand > 0 && r.rate > 0 ? ' · ~' + r.qtyLand.toLocaleString('en-US') + ' left on landing' : '') }));\n        if (r.avail === 'now') return", 'takeoffCell');

// banner under the toolbar
h = rep(h, "        // best routes: the best item of each country, three best countries", "        { const fd = firstDeparture(); if (fd.at > now + 1) main.appendChild(h('div', { class: 'note info' }, h('b', { text: 'My position. ' }), fd.why + clock(fd.at) + inTxt(fd.at, now) + '. Take-off times below start from then (' + MY_DELAY + ' s minimum after landing).')); }\n        // best routes: the best item of each country, three best countries", 'banner');

src = src.replace(m[0], () => 'const DASHBOARD_HTML = ' + JSON.stringify(h).replace(/<\//g, '<\\/') + ';');
fs.writeFileSync(out, src);
console.log('ok', out);
