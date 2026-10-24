/*WSIM-SCHEMA-BEGIN*/
const SIM_SCHEMA = `CREATE TABLE IF NOT EXISTS sim_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, kind TEXT NOT NULL, label TEXT, params TEXT NOT NULL, summary TEXT, result TEXT NOT NULL)`;
SCHEMA_STATEMENTS.push(SIM_SCHEMA);
/*WSIM-SCHEMA-END*/
/*WSIM-BEGIN*/
// ================= Admin simulations =================
// The server only hands out the recorded data (stock history, restocks, player flights) and stores the finished runs;
// the maths run in the admin's browser (same TSIM engine as the planner), so a long simulation never hits the Worker CPU limit.
const SIM_MAX_RESULT = 400000;
const SIM_HIST_LIMIT = 120000;
const SIM_KEEP = 60;
const SIM_CODE = Object.fromEntries(Object.entries(STOCK_COUNTRIES).map(([code, name]) => [name, code]));

function simInt(v, lo, hi, d) { const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= lo && n <= hi ? n : d; }

async function simPlayers(env) {
  const rows = (await env.DB.prepare(`
    SELECT f.player_id AS id, p.name AS name, c.name AS company, COUNT(*) AS flights, MAX(f.takeoff_at) AS last
    FROM radar_flights f LEFT JOIN radar_players p ON p.player_id = f.player_id LEFT JOIN radar_companies c ON c.company_id = f.company_id
    GROUP BY f.player_id ORDER BY flights DESC, last DESC LIMIT 300
  `).all()).results || [];
  return { ok: true, players: rows.map(r => ({ id: String(r.id), name: r.name || ("#" + r.id), company: r.company || "", flights: Number(r.flights), last: Number(r.last) })) };
}

async function simData(env, params) {
  const kind = params.get("kind");
  const now = nowSeconds();
  const from = simInt(params.get("from"), 1500000000, now + 86400, now - 86400), to = simInt(params.get("to"), from, now + 7 * 86400, now);
  if (to - from > 14 * 86400) return { ok: false, message: "Choose a period of 14 days at most." };
  const many = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results || [];
  let flights = [], codes = [];

  if (kind === "follow") {
    const pid = simInt(params.get("player"), 1, 9999999999, 0);
    if (!pid) return { ok: false, message: "Choose a player." };
    flights = (await many(`SELECT takeoff_at, country, direction, plane, duration FROM radar_flights WHERE player_id = ? AND takeoff_at BETWEEN ? AND ? ORDER BY takeoff_at LIMIT 400`, pid, from, to))
      .map(r => ({ takeoffAt: Number(r.takeoff_at), country: r.country, direction: r.direction === "return" ? "return" : "out", plane: r.plane || null }));
    codes = [...new Set(flights.map(f => SIM_CODE[f.country]).filter(Boolean))];
  } else if (kind === "check" || kind === "planner") {
    const wanted = String(params.get("countries") || "").split(",").map(s => s.trim()).filter(Boolean);
    codes = wanted.length ? wanted.map(n => SIM_CODE[n]).filter(Boolean) : Object.keys(STOCK_COUNTRIES);
  } else return { ok: false, message: "Unknown simulation kind." };
  if (!codes.length) return { ok: true, now, travelSec: travelTable(), flights, countries: {}, hist: {}, events: {}, cycles: {}, truncated: false };

  const js = JSON.stringify(codes), end = to + 8 * 3600;
  const snaps = await many(`SELECT country, items FROM stock_snapshot WHERE country IN (SELECT value FROM json_each(?))`, js);
  const prices = new Map((await many(`SELECT item_id, market_value FROM item_prices`)).map(r => [Number(r.item_id), Number(r.market_value)]));
  const countries = {};
  for (const r of snaps) {
    let items = []; try { items = JSON.parse(r.items); } catch { items = []; }
    countries[STOCK_COUNTRIES[r.country] || r.country] = { code: r.country, items: items.map(it => ({ id: it[0], name: it[1], qty: it[2], cost: it[3], market: prices.get(Number(it[0])) || 0 })) };
  }
  const base = await many(`
    SELECT h.country, h.item_id, h.ts, h.qty FROM stock_hist h
    JOIN (SELECT country, item_id, MAX(ts) AS m FROM stock_hist WHERE ts < ? AND country IN (SELECT value FROM json_each(?)) GROUP BY country, item_id) x
      ON x.country = h.country AND x.item_id = h.item_id AND x.m = h.ts
  `, from - 600, js);
  const win = await many(`SELECT country, item_id, ts, qty FROM stock_hist WHERE ts >= ? AND ts <= ? AND country IN (SELECT value FROM json_each(?)) ORDER BY ts LIMIT ?`, from - 600, end, js, SIM_HIST_LIMIT);
  const hist = {};
  for (const r of base.concat(win)) (hist[r.country + "|" + r.item_id] = hist[r.country + "|" + r.item_id] || []).push([Number(r.ts), Number(r.qty)]);
  const out = { ok: true, now, travelSec: travelTable(), flights, countries, hist, events: {}, cycles: {}, truncated: win.length >= SIM_HIST_LIMIT };
  if (kind === "planner") {
    for (const r of await many(`SELECT country, item_id, seen_at FROM stock_events WHERE seen_at >= ? AND seen_at <= ? AND country IN (SELECT value FROM json_each(?)) ORDER BY seen_at LIMIT 60000`, from - 15 * 86400, end, js))
      (out.events[r.country + "|" + r.item_id] = out.events[r.country + "|" + r.item_id] || []).push(Number(r.seen_at));
    for (const r of await many(`SELECT country, item_id, start_at, qty_start, soldout_at FROM stock_cycle WHERE start_at >= ? AND start_at <= ? AND country IN (SELECT value FROM json_each(?)) ORDER BY start_at LIMIT 60000`, from - 8 * 86400, end, js))
      (out.cycles[r.country + "|" + r.item_id] = out.cycles[r.country + "|" + r.item_id] || []).push({ start: Number(r.start_at), qty: Number(r.qty_start), soldout: Number(r.soldout_at) });
  }
  return out;
}

async function simApi(request, env, url, path) {
  if (path === "/admin/sim/players" && request.method === "GET") return json(await simPlayers(env));
  if (path === "/admin/sim/data" && request.method === "GET") { const d = await simData(env, url.searchParams); return json(d, d.ok ? 200 : 400); }
  if (path !== "/admin/sim/runs") return json({ ok: false, message: "Unknown route" }, 404);
  if (request.method === "GET") {
    const id = simInt(url.searchParams.get("id"), 1, 2147483647, 0);
    if (id) {
      const r = await env.DB.prepare(`SELECT id, created_at, kind, label, params, summary, result FROM sim_runs WHERE id = ?`).bind(id).first();
      if (!r) return json({ ok: false, message: "Not found" }, 404);
      return json({ ok: true, run: { id: r.id, createdAt: r.created_at, kind: r.kind, label: r.label, params: JSON.parse(r.params), summary: JSON.parse(r.summary || "null"), result: JSON.parse(r.result) } });
    }
    const rows = (await env.DB.prepare(`SELECT id, created_at, kind, label, params, summary FROM sim_runs ORDER BY id DESC LIMIT ?`).bind(SIM_KEEP).all()).results || [];
    return json({ ok: true, runs: rows.map(r => ({ id: r.id, createdAt: r.created_at, kind: r.kind, label: r.label, params: JSON.parse(r.params), summary: JSON.parse(r.summary || "null") })) });
  }
  if (request.method === "POST") {
    let body = {}; try { body = await request.json(); } catch { body = {}; }
    if (body.delete !== undefined) { await env.DB.prepare(`DELETE FROM sim_runs WHERE id = ?`).bind(simInt(body.delete, 1, 2147483647, 0)).run(); return json({ ok: true }); }
    if (!["follow", "planner", "check"].includes(body.kind)) return json({ ok: false, message: "Unknown simulation kind." }, 400);
    const result = JSON.stringify(body.result === undefined ? null : body.result);
    if (result.length > SIM_MAX_RESULT) return json({ ok: false, message: "Result too large to save (" + Math.round(result.length / 1000) + " KB)." }, 413);
    const label = cleanText(body.label, 80), params = JSON.stringify(body.params || {}).slice(0, 4000), summary = JSON.stringify(body.summary || null).slice(0, 4000);
    const res = await env.DB.prepare(`INSERT INTO sim_runs (created_at, kind, label, params, summary, result) VALUES (?, ?, ?, ?, ?, ?)`).bind(nowSeconds(), body.kind, label, params, summary, result).run();
    await env.DB.prepare(`DELETE FROM sim_runs WHERE id NOT IN (SELECT id FROM sim_runs ORDER BY id DESC LIMIT ?)`).bind(SIM_KEEP).run();
    return json({ ok: true, id: res.meta && res.meta.last_row_id });
  }
  return json({ ok: false, message: "Method not allowed" }, 405);
}
/*WSIM-END*/
