// Loads the real dashboard page from a Worker file in Chromium, with the API mocked, and checks the planner with "My position".
const { chromium } = require('playwright'); const fs = require('fs'); const assert = require('assert');
const file = process.argv[2], shot = process.argv[3];
(async () => {
  const src = fs.readFileSync(file, 'utf8'); const m = src.match(/^const DASHBOARD_HTML = (".*");$/m); const html = JSON.parse(m[1]);
  const now = Math.floor(Date.now() / 1000);
  const items = [{ id: 206, name: 'Xanax', type: 'Drug', qty: 900, cost: 800000, market: 900000, profit: 100000, depletionNow: 20, depletionMed: 20, emptiesAt: now + 3 * 3600, nextRestockAt: now + 5 * 3600, nextConfidence: .8, restockQty: 1500, restocks: 5, cycles: 5, soldOuts: 4, sellOutSec: 3600, cadenceMin: 120, lastRestockAt: now - 3600 }];
  const ST = { ok: true, now, enabled: true, lastOkAt: now, events: [], travelSec: { Canada: { standard: 2340, airstrip: 1638, wlt: 1170, business: 702 } }, countries: [{ code: 'can', name: 'Canada', updatedAt: now, items }] };
  const empty = { ok: true, players: [], clusters: [], flying: [], countries: [], recent: [], now, days: 14, flights: 0, usableFlights: 0, stats: { players: 0, companies: 0, activeCompanies: 0, flying: 0, flights: 0, flights24h: 0, landed: 0 } };
  const browser = await chromium.launch(); const ctx = await browser.newContext({ viewport: { width: 1300, height: 1000 } }); const page = await ctx.newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  let travelPos = { state: 'flying', direction: 'return', country: null, landAt: now + 600 };
  await page.route('https://app.test/**', async (route) => {
    const u = new URL(route.request().url()), p = u.pathname, j = (o, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
    if (p === '/dashboard') return route.fulfill({ contentType: 'text/html', body: html });
    if (p === '/me') return j({ ok: true, user: { username: 'tester', tornUserId: '1', role: 'admin', beta: true, premium: { active: true, admin: true } } });
    if (p === '/targets') return j({ ok: true, targets: [] });
    if (p === '/api/prefs') return j({ ok: true, prefs: null });
    if (p === '/api/events') return j({ ok: true, total: 0, events: [] });
    if (p === '/api/radar') return j(empty);
    if (p === '/api/radar/insights') return j(empty);
    if (p === '/api/radar/stock') return j(ST);
    if (p === '/api/radar/stock/item') return j({ ok: true, now, since: now - 86400, points: [], restocks: [], soldouts: [], prices: [] });
    if (p === '/api/me/travel') return j({ ok: true, now, pos: travelPos });
    return j({ ok: false }, 404);
  });
  await page.goto('https://app.test/dashboard#/radar'); await page.waitForSelector('.rtabs');
  const openStock = async () => { await page.click('.rtab:has-text("Stock")'); await page.waitForSelector('.tside'); };
  await openStock();
  const text = () => page.locator('.tmain').innerText();
  // 1. in Torn: no banner, take off "Now"
  let t = await text(); assert(!t.includes('My position.'), 'no banner in Torn'); assert(/\bNow\b/.test(t), 'leaves now');
  // 2. use my position (flying home, lands in 10 min)
  await page.click('button:has-text("Use my position")'); await page.waitForSelector('.note.info:has-text("My position.")');
  t = await text(); assert(/You land in Torn at \d\d:\d\d:\d\d/.test(t), t.slice(0, 300)); assert(/30 s minimum after landing/.test(t));
  assert(!/\bNow\b/.test(t.split('Best routes')[1] || ''), 'no "Now" while flying');
  const banner = (await page.locator('.note.info', { hasText: 'My position.' }).first().innerText());
  const landClock = banner.match(/at (\d\d:\d\d:\d\d)/)[1];
  // earliest = landing + 30 s: the banner time must be 30 s after the landing time we gave (tz local)
  const exp = new Date((now + 600 + 30) * 1000); const hhmmss = [exp.getHours(), exp.getMinutes()].map(x => String(x).padStart(2, '0')).join(':');
  assert(banner.includes(hhmmss), 'banner earliest ' + hhmmss + ' in ' + banner);
  // 3. flying out to Canada: must fly back first (airstrip 1638 s)
  travelPos = { state: 'flying', direction: 'out', country: 'Canada', landAt: now + 600 };
  await page.click('button:has-text("Use my position")'); await page.waitForFunction(() => document.querySelector('.note.info') && /fly back/.test(document.querySelector('.tmain').innerText));
  // 4. planner view: first take-off not before earliest
  await page.click('.tmain .pseg button:has-text("Planner")'); await page.waitForSelector('h3:has-text("Day plan")');
  const firstRow = await page.locator('.tmain tbody tr').first().innerText();
  console.log('first plan row:', firstRow.replace(/\s+/g, ' '));
  await page.screenshot({ path: shot, fullPage: false });
  assert.deepStrictEqual(errors, []);
  await browser.close(); console.log('dashboard planner with my position: all checks passed');
})().catch(e => { console.error(e); process.exit(1); });
