// ==UserScript==
// @name         TornScope
// @namespace    tornscope
// @homepageURL  https://app.tornscope.com
// @supportURL   https://app.tornscope.com
// @version      3.6
// @description  Track Torn players: flights, landings, alarms, War mode and Premium server tracking. Works with the TornScope site and Torn PDA | Developer: Zeussh (4268037)
// @match        https://www.torn.com/*
// @run-at       document-end
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_notification
// @grant        GM_xmlhttpRequest
// @connect      torn-travel-watcher.sci-msolak.workers.dev
// ==/UserScript==

(function () {
  'use strict';

  /* ================= Fixed settings ================= */
  // Project developer: Zeussh (Torn ID 4268037)
  const API_CAP = 90;          // max requests / minute (Torn limit: 100 per key)
  // Torn PDA replaces this placeholder with the API key configured in the app.
  const PDA_API_KEY = '###PDA-APIKEY###';
  const WORKER_URL = 'https://torn-travel-watcher.sci-msolak.workers.dev';
  const SLOW = 60000;          // target in Torn but inactive
  const ABROAD = 20000;        // target abroad
  const OTHER = 30000;         // hospital, jail...
  const ONLINE_WINDOW = 300;   // seconds: active within the last 5 min = "online"
  const VERSION = '3.6';
  const TRAVEL_URL = 'https://www.torn.com/page.php?sid=travel';
  const SITE_URL = 'https://app.tornscope.com';
  const LOGO = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none"><g stroke="currentColor" stroke-linecap="round" fill="none"><circle cx="32" cy="32" r="29" stroke-width="3"/><circle cx="32" cy="32" r="19" stroke-width="2" stroke-opacity=".75"/><circle cx="32" cy="32" r="9" stroke-width="2" stroke-opacity=".75"/><path d="M32 4v13M32 47v13M4 32h13M47 32h13" stroke-width="1.5" stroke-opacity=".5"/></g><path d="M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z" fill="#16D9F2" fill-opacity="0.07"/><path d="M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z" fill="#16D9F2" fill-opacity="0.12"/><path d="M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z" fill="#16D9F2" fill-opacity="0.19"/><path d="M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z" fill="#16D9F2" fill-opacity="0.3"/><path d="M32 32L61.0 31.0" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/><circle cx="47" cy="19" r="3.6" fill="var(--blip,#fff)" fill-opacity=".2"/><circle cx="47" cy="19" r="2.3" fill="var(--blip,#fff)"/><circle cx="41" cy="11.5" r="1.5" fill="var(--blip,#fff)" fill-opacity=".85"/><circle cx="32" cy="32" r="3" fill="currentColor"/></svg>';
  const CROWN = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 80" fill="none"><g transform="translate(0 16)"><g stroke="currentColor" stroke-linecap="round" fill="none"><circle cx="32" cy="32" r="29" stroke-width="3"/><circle cx="32" cy="32" r="19" stroke-width="2" stroke-opacity=".75"/><circle cx="32" cy="32" r="9" stroke-width="2" stroke-opacity=".75"/><path d="M32 4v13M32 47v13M4 32h13M47 32h13" stroke-width="1.5" stroke-opacity=".5"/></g><path d="M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z" fill="#16D9F2" fill-opacity="0.07"/><path d="M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z" fill="#16D9F2" fill-opacity="0.12"/><path d="M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z" fill="#16D9F2" fill-opacity="0.19"/><path d="M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z" fill="#16D9F2" fill-opacity="0.3"/><path d="M32 32L61.0 31.0" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/><circle cx="47" cy="19" r="3.6" fill="var(--blip,#fff)" fill-opacity=".2"/><circle cx="47" cy="19" r="2.3" fill="var(--blip,#fff)"/><circle cx="41" cy="11.5" r="1.5" fill="var(--blip,#fff)" fill-opacity=".85"/><circle cx="32" cy="32" r="3" fill="currentColor"/></g><g transform="translate(2 0) scale(1.0)"><path d="M15 24L11 7l9 7 7-12 7 12 9-7-4 17z" fill="#F5B72E" stroke="#C98A0B" stroke-width="1.2" stroke-linejoin="round"/><path d="M15 24L11 7l9 7 7-12 7 12" fill="none" stroke="#FFE08A" stroke-width="1" stroke-linejoin="round" stroke-opacity=".8" transform="translate(0 .2)"/><rect x="15" y="24" width="30" height="5" rx="1.5" fill="#F5B72E" stroke="#C98A0B" stroke-width="1.2"/><circle cx="11" cy="7" r="2.2" fill="#FFE08A"/><circle cx="27" cy="2" r="2.4" fill="#FFE08A"/><circle cx="49" cy="7" r="2.2" fill="#FFE08A"/><circle cx="30" cy="26.5" r="1.3" fill="#16D9F2"/><circle cx="22" cy="26.5" r="1" fill="#fff" fill-opacity=".8"/><circle cx="38" cy="26.5" r="1" fill="#fff" fill-opacity=".8"/></g></svg>';
  const SYNC_EVERY = 60000;            // dashboard <-> script sync interval
  const SYNC_RETRY_UNSYNCED = 600000;  // how often to retry targets the server refused
  const EVENTS_MAX = 500;              // max flight events kept while the server is unreachable
  const EVENTS_BATCH = 50;             // events per request (server limit)

  /* ================= Base flight times + aircraft ================= */
  const BASE_MIN = {
    'Mexico': 25, 'Cayman Islands': 33, 'Canada': 39, 'Hawaii': 127, 'United Kingdom': 151,
    'Argentina': 158, 'Switzerland': 166, 'Japan': 213, 'China': 229,
    'United Arab Emirates': 257, 'South Africa': 281
  };
  const PLANES = [
    ['Standard', 1.00], ['Airstrip', 0.70], ['WLT', 0.50], ['Business', 0.30],
    ['Standard+book', 0.75], ['Airstrip+book', 0.53], ['WLT+book', 0.38], ['Business+book', 0.23]
  ];
  function guessPlane(desc, mins) {
    const c = Object.keys(BASE_MIN).find(k => desc.includes(k));
    if (!c) return null;
    const ratio = mins / BASE_MIN[c];
    const r = PLANES.map(([n, v]) => ({ n, d: Math.abs(ratio - v) })).sort((a, b) => a.d - b.d);
    const best = r.filter(x => x.d - r[0].d < 0.04 && x.d < 0.08).slice(0, 2);
    return best.length ? best.map(x => x.n).join(' ou ') : null;
  }

  /* ================= Storage ================= */
  const hasGM = typeof GM_getValue === 'function' && typeof GM_setValue === 'function';
  const TAG = '{"__ttw":1';
  const encode = (v) => JSON.stringify({ __ttw: 1, v });
  const decode = (raw, d) => {
    if (raw === undefined || raw === null) return d;
    if (typeof raw === 'string' && raw.startsWith(TAG)) { try { return JSON.parse(raw).v; } catch (e) { return d; } }
    return raw; // legacy value written by an older version
  };
  const store = {
    get(k, d) {
      try {
        let raw;
        if (hasGM) { raw = GM_getValue('ttw_' + k); if (raw && typeof raw.then === 'function') raw = undefined; }
        if (raw === undefined || raw === null) {
          raw = localStorage.getItem('ttw_' + k);
          if (typeof raw === 'string' && !raw.startsWith(TAG)) { try { raw = JSON.parse(raw); } catch (e) {} }
        }
        return decode(raw, d);
      } catch (e) { return d; }
    },
    set(k, v) {
      const enc = encode(v);
      try { if (hasGM) GM_setValue('ttw_' + k, enc); } catch (e) {}
      try { localStorage.setItem('ttw_' + k, enc); } catch (e) {}
    }
  };
  const tabId = (() => {
    try {
      let t = sessionStorage.getItem('ttw_tab');
      if (!t) { t = Math.random().toString(36).slice(2); sessionStorage.setItem('ttw_tab', t); }
      return t;
    } catch (e) { return Math.random().toString(36).slice(2); }
  })();
  const lockOk = () => { const l = store.get('lock', null); return !l || typeof l !== 'object' || l.id === tabId || !(l.until > Date.now()); };
  const takeLock = () => store.set('lock', { id: tabId, until: Date.now() + 20000 });

  /* ================= Account scope + overlay token ================= */
  // `account` is set only after the Worker has confirmed which Torn account the overlay token
  // belongs to. Until then we are either in local-only mode (no token) or waiting for the first
  // successful sync. Per-account data lives under *_<TornID> keys so accounts never mix.
  let account = null;   // { id, name }
  let premium = null;   // { active, admin, until } as last reported by the Worker
  let siteBase = SITE_URL;
  const sync = { state: 'off', text: '', at: 0, busy: false, last: 0, retryUnsyncedAt: 0, unsynced: 0 };
  let autoResume = false;

  // The overlay token is kept in Tampermonkey storage only (never mirrored to the page's
  // localStorage unless the userscript manager cannot store it).
  const secret = {
    get(k) {
      try {
        if (hasGM) {
          const v = GM_getValue('ttw_' + k);
          if (v && typeof v.then === 'function') throw new Error('async');
          const d = decode(v, undefined);
          if (d !== undefined && d !== null) return d;
        }
      } catch (e) {}
      try { const raw = localStorage.getItem('ttw_' + k); return raw === null ? undefined : decode(raw, undefined); } catch (e) { return undefined; }
    },
    set(k, v) {
      const enc = encode(v); let ok = false;
      try { if (hasGM) { GM_setValue('ttw_' + k, enc); ok = GM_getValue('ttw_' + k) === enc; } } catch (e) {}
      try { if (ok) localStorage.removeItem('ttw_' + k); else localStorage.setItem('ttw_' + k, enc); } catch (e) {}
    }
  };
  let tokenMem = null;
  const getOverlayToken = () => {
    if (tokenMem === null) { const t = String(secret.get('overlayToken') || '').trim(); tokenMem = /^[a-f0-9]{64}$/i.test(t) ? t : ''; }
    return tokenMem;
  };
  const setOverlayToken = (t) => { secret.set('overlayToken', t); tokenMem = t; };
  // Short non-reversible fingerprint, used only to remember which account a token belonged to.
  const tokenFp = (s) => {
    let h1 = 0xdeadbeef ^ s.length, h2 = 0x41c6ce57 ^ s.length;
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 2654435761); h2 = Math.imul(h2 ^ c, 1597334677); }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h2 >>> 0).toString(16) + (h1 >>> 0).toString(16);
  };

  // A token is set but the Worker has not confirmed the account yet: never touch any list.
  const unverified = () => !!getOverlayToken() && !account;
  const targetsKey = () => account ? 'targets_' + account.id : 'targets';
  const normTarget = (t) => ({
    id: String(t.id), name: t.name || '', lastUntil: Number(t.lastUntil) || 0,
    lastFlightKey: t.lastFlightKey || '', lastSrc: t.lastSrc || '', plane: PLANES.some(([n]) => n === t.plane) ? t.plane : 'Airstrip'
  });
  const readTargets = (key) => {
    const v = store.get(key, []);
    return Array.isArray(v) ? v.filter(t => t && /^\d+$/.test(String(t.id))).map(normTarget) : [];
  };
  const cfg = () => ({
    fast: Math.max(3, Math.min(30, +store.get('fast', 5) || 5)),
    sound: store.get('sound', true) !== false,
    loop: store.get('loop', true) !== false,
    notif: store.get('notif', true) !== false
  });
  const getApiKey = () => !PDA_API_KEY.startsWith('###PDA-') ? PDA_API_KEY : String(store.get('key', '') || '');
  const isPDA = () => typeof window.PDA_httpGet === 'function';
  const maxTargets = () => Math.max(1, Math.floor(API_CAP * cfg().fast / 60));

  // Old single global list (v1 / 2.5). With a token configured it is imported once into the
  // first account that connects; it is never copied to a second account.
  const legacyTargets = () => {
    let l = readTargets('targets');
    if (!l.length && store.get('target', '')) l = [normTarget({ id: String(store.get('target')) })]; // migration v1
    return l;
  };
  let targets = getOverlayToken() ? [] : legacyTargets();
  const saveTargets = () => {
    if (unverified()) return; // never write while the account is not confirmed
    store.set(targetsKey(), targets.map(normTarget));
  };

  // Fallback only: use this when the API does not provide a usable landing timestamp.
  function estimateFlightMinutes(desc, planeName) {
    const destination = Object.keys(BASE_MIN).find(city => String(desc || '').includes(city));
    if (!destination) return null;
    const plane = PLANES.find(([name]) => name === (planeName || 'Airstrip'));
    return plane ? Math.max(1, Math.round(BASE_MIN[destination] * plane[1])) : null;
  }

  // Destination / direction from Torn's wording (works whatever the exact sentence is).
  const ALIASES = { 'cayman': 'Cayman Islands', 'uk': 'United Kingdom', 'uae': 'United Arab Emirates' };
  function destOf(desc) {
    const d = String(desc || '');
    const known = Object.keys(BASE_MIN).find(k => d.includes(k));
    if (known) return known;
    const low = ' ' + d.toLowerCase().replace(/[^a-z ]/g, ' ') + ' ';
    const al = Object.keys(ALIASES).find(k => low.includes(' ' + k + ' '));
    if (al) return ALIASES[al];
    const ft = d.match(/^Travell?ing from (.{2,40}?) to (.{2,40})$/i);
    if (ft) return (/^torn$/i.test(ft[2].trim()) ? ft[1] : ft[2]).trim();
    const m = d.match(/^Travell?ing to (.{2,40})$/i) || d.match(/from (.{2,40})$/i) || d.match(/^In (.{2,40})$/i);
    return m ? m[1].trim() : '';
  }
  const isReturn = (desc) => { const d = String(desc || '').trim(); return /^returning/i.test(d) || /^travell?ing from .{2,40} to torn$/i.test(d); };

  const live = {};
  const ensureLive = (t) => (live[t.id] = live[t.id] || { state: '', desc: '', until: 0, untilSrc: '', polledAt: 0, rel: '', mode: '', nextAt: 0, seen: false, busy: false, err: '', t0: null, flash: 0 });
  targets.forEach(t => { if (!t.plane) t.plane = 'Airstrip'; ensureLive(t); });

  /* ================= Sound + notification ================= */
  let actx;
  function ensureAudio() {
    try { actx = actx || new (window.AudioContext || window.webkitAudioContext)(); if (actx.state === 'suspended') actx.resume(); } catch (e) {}
  }
  document.addEventListener('click', ensureAudio);
  function beep() {
    ensureAudio(); if (!actx) return;
    [0, 0.25, 0.5, 0.75].forEach((o, i) => {
      const osc = actx.createOscillator(), g = actx.createGain();
      osc.frequency.value = i % 2 ? 880 : 1175; g.gain.value = 0.2;
      osc.connect(g); g.connect(actx.destination);
      osc.start(actx.currentTime + o); osc.stop(actx.currentTime + o + 0.18);
    });
  }
  let alarmActive = false, lastBeep = 0, alarmInfo = { name: '', dest: '' };
  const alarmOn = () => alarmActive;
  function startAlarm(info) {
    if (info) alarmInfo = { name: String(info.name || ''), dest: String(info.dest || '') };
    alarmActive = true;
    beep(); lastBeep = Date.now();
    render();
  }
  function stopAlarm() { alarmActive = false; render(); }

  function notify(title, text) {
    // Torn PDA can turn GM_notification into a native iOS notification.
    try {
      if (typeof GM_notification === 'function') {
        GM_notification({ title, text, timeout: 0,
          onclick: () => { try { window.focus(); } catch (e) {} } });
        return;
      }
    } catch (e) {}
    try {
      if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
        const n = new Notification(title, { body: text, requireInteraction: true });
        n.onclick = () => { try { window.focus(); } catch (e) {} n.close(); };
      }
    } catch (e) {}
  }

  /* ================= Shared polling engine ================= */
  let running = false, reqLog = [], lastLock = 0, worker = null, fallback = null;

  function startTimer() {
    stopTimer();
    try {
      worker = new Worker(URL.createObjectURL(new Blob(['setInterval(()=>postMessage(0),1000)'], { type: 'text/javascript' })));
      worker.onmessage = tick;
      worker.onerror = () => { worker = null; if (!fallback) fallback = setInterval(tick, 1000); };
    } catch (e) { worker = null; fallback = setInterval(tick, 1000); }
  }
  function stopTimer() {
    if (worker) { worker.terminate(); worker = null; }
    if (fallback) { clearInterval(fallback); fallback = null; }
  }

  function tick() {
    if (!running) return;
    if (alarmOn() && Date.now() - lastBeep >= 2500) { beep(); lastBeep = Date.now(); }
    if (!lockOk()) { stop(false, 'Active in another tab'); return; }
    const now = Date.now();
    if (now - lastLock > 5000) { takeLock(); lastLock = now; }
    reqLog = reqLog.filter(t => now - t < 60000);
    if (warOn()) { warTick(now); return; }
    const due = targets.filter(t => ensureLive(t).nextAt <= now && !live[t.id].busy)
                       .sort((a, b) => live[a.id].nextAt - live[b.id].nextAt);
    let fired = 0;
    for (const t of due) {
      if (reqLog.length >= API_CAP || fired >= 2) break;
      reqLog.push(now); fired++; poll(t);
    }
  }

  async function poll(t) {
    const L = live[t.id]; L.busy = true;
    try {
      const url = `https://api.torn.com/user/${encodeURIComponent(t.id)}?selections=profile&key=${encodeURIComponent(getApiKey())}&comment=TravelWatcher`;
      let d;
      if (isPDA()) {
        const response = await window.PDA_httpGet(url);
        if (!response || (response.status && (response.status < 200 || response.status >= 300))) throw new Error('PDA HTTP error');
        d = JSON.parse(response.responseText || '{}');
      } else {
        const r = await fetch(url);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        d = await r.json();
      }
      if (!targets.includes(t)) { /* target removed or account switched while the request was in flight: ignore */ }
      else if (d.error) onError(t, L, d.error); else onProfile(t, L, d);
    } catch (e) { L.err = 'Network/PDA error'; L.nextAt = Date.now() + 10000; }
    L.busy = false;
  }

  function onError(t, L, e) {
    L.err = `API ${e.code}: ${e.error}`;
    if ([2, 10, 13, 18].includes(e.code)) { stop(true, 'API key invalid or disabled'); return; }
    L.nextAt = Date.now() + (e.code === 6 ? 60000 : 10000);
  }

  // Take-off rebuilt from the landing time Torn gives us, when a check came a little late (the target
  // became active and flew before we looked). Used only when the aircraft fits the window between the
  // last check on the ground and this one: nothing is invented otherwise. Precision: about a minute.
  function inferTakeoff(country, untilSec, nowSec, windowStartSec, preferred) {
    const base = country ? BASE_MIN[country] : 0;
    if (!base || !(untilSec > nowSec) || !(windowStartSec > 0)) return null;
    const fits = [];
    PLANES.forEach(([name, f]) => {
      const start = untilSec - Math.round(base * f * 60);
      if (start >= windowStartSec - 5 && start <= nowSec + 5) fits.push({ name, start });
    });
    if (!fits.length) return null;
    const chosen = fits.find(x => x.name === preferred);
    if (chosen) return Math.min(nowSec, Math.max(windowStartSec, chosen.start));
    const distinct = fits.filter((v, i) => fits.findIndex(w => Math.abs(w.start - v.start) <= 30) === i);
    return distinct.length === 1 ? Math.min(nowSec, Math.max(windowStartSec, distinct[0].start)) : null;
  }

  function onProfile(t, L, d) {
    const st = d.status || {}, la = d.last_action || {}, now = Date.now(), nowSec = Math.floor(now / 1000);
    if (d.name && t.name !== d.name) { t.name = d.name; saveTargets(); }

    const previousState = L.state;
    const previousUntil = L.until || 0;
    const previousDesc = L.desc || '';
    const previousPoll = L.polledAt || 0;
    const first = !L.seen;
    const enteredFlight = st.state === 'Traveling' && !first && previousState !== 'Traveling';
    L.seen = true;
    L.err = '';
    L.polledAt = nowSec;
    L.state = st.state;
    L.desc = st.description || st.state || '';
    // Some wordings keep the country in `details`: use it only when the description has none.
    if (st.state === 'Traveling' && !destOf(L.desc) && st.details && destOf(st.details)) L.desc = (L.desc + ' ' + st.details).slice(0, 80);
    L.rel = la.relative || '';

    // Observed transitions (never reconstructed): reported to the site through the outbox.
    if (!first && previousState && previousState !== st.state && st.state && st.state !== 'Traveling') {
      queueEvent({
        clientId: t.id + '|' + (previousState === 'Traveling' ? 'arrival' : 'state_change') + '|' + nowSec,
        targetId: t.id, targetName: t.name || t.id,
        type: previousState === 'Traveling' ? 'arrival' : 'state_change',
        stateFrom: previousState, stateTo: st.state, description: L.desc,
        observedAt: nowSec, landingAt: previousState === 'Traveling' && previousUntil ? previousUntil : null,
        quality: 'observed', plane: t.plane || ''
      });
    }

    if (st.state === 'Traveling') {
      const rawUntil = Number(st.until) || 0;
      const apiUntil = rawUntil > nowSec ? rawUntil : 0;
      const dest = destOf(L.desc);
      // A different route while still "Traveling" = we missed the landing and the next take-off (return flight).
      const routeChanged = !first && previousState === 'Traveling' && !!previousDesc && previousDesc !== L.desc;
      const newFlight = enteredFlight || routeChanged;
      const estimatedMins = estimateFlightMinutes(L.desc, t.plane || 'Airstrip');
      const sameRoute = (k) => { k = String(k || ''); return k === L.desc || k === 'estimate:' + L.desc || k.startsWith(L.desc + '|'); };

      // Never pretend a flight already in progress just departed when this script starts/reloads.
      if (apiUntil) { L.until = apiUntil; L.untilSrc = 'api'; }
      else if (!newFlight && previousState === 'Traveling' && previousUntil > nowSec) { L.until = previousUntil; }
      else if (first && sameRoute(t.lastFlightKey) && Number(t.lastUntil) > nowSec) { L.until = Number(t.lastUntil); L.untilSrc = t.lastSrc || 'estimate'; }
      else if (newFlight && estimatedMins) { L.until = nowSec + estimatedMins * 60; L.untilSrc = 'estimate'; }
      else { L.until = 0; L.untilSrc = ''; }

      // One flight = one record: the identity of a flight is its route, not its landing time.
      const record = newFlight || (first && !sameRoute(t.lastFlightKey));
      if (record) {
        let depSec = nowSec, quality = first ? 'in_flight' : 'observed';
        if (!first) {
          const windowStart = routeChanged && previousUntil ? previousUntil : previousPoll;
          const guessed = inferTakeoff(dest, apiUntil, nowSec, windowStart, t.plane);
          if (guessed && nowSec - guessed > 20) { depSec = guessed; quality = 'inferred'; }
        }
        L.t0 = first ? null : depSec * 1000;
        t.lastFlightKey = L.desc; t.lastUntil = L.until || 0; t.lastSrc = L.untilSrc || '';
        saveTargets();
        queueEvent({
          clientId: t.id + '|departure|' + depSec,
          targetId: t.id, targetName: t.name || t.id, type: 'departure',
          stateFrom: previousState || null, stateTo: 'Traveling', description: L.desc,
          observedAt: depSec,
          landingAt: L.until || null, landingSource: apiUntil ? 'api' : (L.until ? 'estimate' : null),
          quality, plane: t.plane || ''
        });
      } else if (L.until && Number(t.lastUntil) !== L.until) { t.lastUntil = L.until; t.lastSrc = L.untilSrc || ''; saveTargets(); }

      if (newFlight) {
        L.flash = now + 12000;
        const c = cfg();
        if (c.sound) startAlarm({ name: t.name || t.id, dest });
        if (c.notif) {
          const remaining = L.until ? Math.max(0, Math.round((L.until * 1000 - now) / 60000)) : null;
          notify(`${t.name || t.id} is traveling!`,
            L.desc + (remaining !== null ? ` — lands in about ${remaining} min${apiUntil ? '' : ' (estimate)'}` : ''));
        }
      }

      L.mode = 'pause';
      // Keep checking even without a landing timestamp, so a changed route/return flight is detected.
      L.nextAt = L.until ? Math.max(now + 5000, L.until * 1000 + 2000) : now + ABROAD;
      return;
    }

    L.t0 = null;
    L.until = 0; L.untilSrc = '';
    if (st.state === 'Okay') {
      const online = la.status === 'Online' || (now / 1000 - (la.timestamp || 0)) < ONLINE_WINDOW;
      L.mode = online ? 'fast' : 'slow'; L.nextAt = now + (online ? cfg().fast * 1000 : SLOW);
    } else if (st.state === 'Abroad') { L.mode = 'abroad'; L.nextAt = now + ABROAD; }
    else { L.mode = 'other'; L.nextAt = now + OTHER; }
  }

  function start() {
    if (unverified()) { msg(sync.state === 'auth' ? 'Overlay token rejected — see Settings' : 'Waiting for the sync server…'); return; }
    if (!getApiKey()) { msg('Enter your API key in Settings, or configure it in Torn PDA'); showTab('s'); return; }
    if (warOn() ? !W.fid : !targets.length) { msg(warOn() ? 'War mode: enter the enemy faction ID' : 'Add at least one target'); if (warOn()) showTab('w'); return; }
    if (!lockOk()) { msg('Already active in another tab'); return; }
    ensureAudio();
    try { if (!isPDA() && typeof Notification !== 'undefined' && Notification.permission === 'default') Notification.requestPermission(); } catch (e) {}
    targets.forEach(t => { const L = ensureLive(t); L.seen = false; L.nextAt = 0; });
    running = true; store.set('running', true); takeLock(); startTimer(); render();
  }
  function stop(persist, text) {
    running = false; stopTimer(); alarmActive = false;
    if (persist !== false) store.set('running', false);
    const l = store.get('lock', null); if (l && l.id === tabId) store.set('lock', null);
    if (text) msg(text);
    render();
  }

  /* ================= Overlay sync (dashboard <-> script) ================= */
  // The Torn API key is never sent anywhere except api.torn.com. Only the overlay token goes to
  // the Worker, in an Authorization header, via GM_xmlhttpRequest (no CORS preflight problem).
  const safeText = (s) => String(s == null ? '' : s).replace(/[a-f0-9]{32,}/gi, '[hidden]').slice(0, 160);
  const clearLive = () => Object.keys(live).forEach(k => { delete live[k]; });

  function overlayRequest(method, path, body) {
    return new Promise((resolve) => {
      const token = getOverlayToken();
      if (!token) return resolve({ status: 0, data: null, error: 'no-token' });
      const url = WORKER_URL + path;
      const headers = { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' };
      const payload = body === undefined ? undefined : JSON.stringify(body);
      if (payload !== undefined) headers['Content-Type'] = 'application/json';
      const finish = (status, text) => {
        let data = null; try { data = JSON.parse(text); } catch (e) {}
        resolve({ status: Number(status) || 0, data, error: null });
      };
      const fail = (kind) => resolve({ status: 0, data: null, error: kind });
      try {
        if (typeof GM_xmlhttpRequest === 'function') {
          GM_xmlhttpRequest({
            method, url, headers, data: payload, timeout: 15000, anonymous: true,
            onload: (r) => finish(r.status, r.responseText),
            onerror: () => fail('network'), ontimeout: () => fail('timeout'), onabort: () => fail('network')
          });
          return;
        }
        // Torn PDA fallback (best effort): PDA_httpGet / PDA_httpPost; DELETE goes through POST .../remove
        if (method === 'GET' && typeof window.PDA_httpGet === 'function') {
          Promise.resolve(window.PDA_httpGet(url, headers)).then((r) => finish(r && r.status, r && r.responseText), () => fail('network'));
          return;
        }
        if ((method === 'POST' || method === 'DELETE') && typeof window.PDA_httpPost === 'function') {
          const target = method === 'DELETE' ? url + '/remove' : url;
          Promise.resolve(window.PDA_httpPost(target, headers, payload || '')).then((r) => finish(r && r.status, r && r.responseText), () => fail('network'));
          return;
        }
        fail('no-transport');
      } catch (e) { fail('network'); }
    });
  }
  const isOk = (r) => r.status >= 200 && r.status < 300 && !!r.data && r.data.ok === true;
  const isTransient = (r) => !!r.error || r.status === 0 || r.status >= 500;

  let chain = Promise.resolve();
  const exclusive = (fn) => { const p = chain.then(fn); chain = p.catch(() => {}); return p; };

  /* ================= Flight events -> dashboard (history / statistics) ================= */
  // Only observed facts are sent: departures, arrivals and state changes of YOUR targets.
  // The Torn API key never leaves this script. Events wait in a per-account outbox until the
  // server confirms them; the server ignores duplicates (clientId), so re-sending is safe.
  const eventsKey = (id) => 'events_' + id;
  function queueEvent(ev) {
    if (unverified() || !account) return;
    const key = eventsKey(account.id);
    const box = store.get(key, []);
    const list = Array.isArray(box) ? box : [];
    if (list.some(x => x && x.clientId === ev.clientId)) return;
    list.push(ev);
    store.set(key, list.slice(-EVENTS_MAX));
    clearTimeout(queueEvent.timer);
    queueEvent.timer = setTimeout(() => { syncNow('events'); }, 1500);
  }
  const pendingEvents = () => { if (!account) return 0; const b = store.get(eventsKey(account.id), []); return Array.isArray(b) ? b.length : 0; };

  async function flushEvents() {
    if (unverified() || !account) return;
    const id = account.id, key = eventsKey(id);
    for (let round = 0; round < 4; round++) {
      const box = store.get(key, []);
      if (!Array.isArray(box) || !box.length) return;
      const hold = unsyncedSet(id); // targets the server does not know yet: keep their events for later
      const batch = box.filter(e => e && !hold.has(String(e.targetId))).slice(0, EVENTS_BATCH);
      if (!batch.length) return;
      const r = await overlayRequest('POST', '/overlay/events', { events: batch });
      if (!account || account.id !== id) return; // account changed while waiting: never mix
      if (!isOk(r)) return;                      // offline / refused: keep everything, retry on the next sync
      const sent = new Set(batch.map(e => e.clientId));
      const fresh = store.get(key, []);
      store.set(key, (Array.isArray(fresh) ? fresh : []).filter(e => e && !sent.has(e.clientId)));
      if (batch.length < EVENTS_BATCH) return;
    }
  }

  function setSync(state, text) { sync.state = state; sync.text = safeText(text || ''); sync.at = Date.now(); }

  function enterAccount(id, name) {
    account = { id: String(id), name: String(name || '') };
    targets = readTargets('targets_' + account.id);
    const cached = store.get('premium_' + account.id, null);
    premium = cached && typeof cached === 'object' ? { active: !!cached.active, admin: !!cached.admin, until: Number(cached.until) || 0 } : null;
    clearLive(); targets.forEach(ensureLive);
  }

  function setPremium(p, site) {
    if (p && typeof p === 'object') {
      premium = { active: !!p.active, admin: !!p.admin, until: Number(p.until) || 0 };
      if (account) store.set('premium_' + account.id, premium);
    }
    if (typeof site === 'string' && /^https:\/\/[a-z0-9.-]+$/i.test(site)) siteBase = site;
  }

  function resetToUnverified() {
    if (running) stop(false);
    account = null; premium = null; targets = []; clearLive();
    sync.retryUnsyncedAt = 0; sync.unsynced = 0; autoResume = false;
    render();
  }

  function maybeAutoStart() {
    if (running || unverified()) return;
    if (store.get('running', false) === true && lockOk() && getApiKey() && (targets.length || (warOn() && W.fid))) start();
  }

  function syncNow(reason) {
    if (!getOverlayToken()) { tokenMem = null; }
    if (!getOverlayToken()) { setSync('off'); return Promise.resolve(); }
    return exclusive(async () => {
      tokenMem = null; // re-read: another tab may have changed it
      if (!getOverlayToken()) { setSync('off'); return; }
      sync.busy = true; sync.last = Date.now();
      try {
        if (!account || reason === 'manual') setSync('connecting', 'Connecting…');
        const r = await overlayRequest('GET', '/overlay/targets');
        await handleSyncResponse(r, reason);
        if (sync.state === 'ok' && account) await flushEvents();
      } catch (e) {
        setSync('error', 'Unexpected sync error');
      } finally {
        sync.busy = false; sync.last = Date.now(); render();
      }
    });
  }

  async function handleSyncResponse(r, reason) {
    if (isTransient(r)) {
      setSync('offline', 'Server unreachable' + (r.error ? ' (' + r.error + ')' : ' (HTTP ' + r.status + ')') + ' — keeping the saved list');
      if (!account) tryCachedAccount();
      return;
    }
    if (r.status === 401) { onAuthFailed(); return; }
    const d = r.data;
    const shaped = r.status >= 200 && r.status < 300 && d && d.ok === true && d.user &&
      /^\d{1,12}$/.test(String(d.user.tornUserId)) && Array.isArray(d.targets);
    if (!shaped) { setSync('error', (d && d.message) ? d.message : 'Unexpected server response (HTTP ' + r.status + ')'); return; }
    const serverList = [], seen = new Set();
    for (const s of d.targets) {
      const tid = String(s && s.tornId);
      if (/^\d{1,12}$/.test(tid) && !seen.has(tid)) { seen.add(tid); serverList.push({ id: tid, name: String(s.name || '') }); }
    }
    // A non-empty answer that parsed to nothing is a malformed response, not an empty list.
    if (d.targets.length > 0 && serverList.length === 0) { setSync('error', 'Unexpected server response'); return; }

    const id = String(d.user.tornUserId);
    let switched = false;
    const premiumNow = d.premium, siteNow = d.siteUrl;
    if (!account || account.id !== id) {
      if (account && running) stop(false);
      enterAccount(id, d.user.username);
      switched = true;
      if (store.get('syncInit_' + id, false) !== true) await initialMerge(id, serverList);
      else await applyServer(serverList, reason);
    } else {
      account.name = String(d.user.username || account.name);
      if (store.get('syncInit_' + id, false) !== true) await initialMerge(id, serverList);
      else await applyServer(serverList, reason);
    }
    if (account && account.id === id) setPremium(premiumNow, siteNow);
    store.set('tokenAcct', { fp: tokenFp(getOverlayToken()), id, name: account ? account.name : '' });
    if (switched && sync.state !== 'auth') maybeAutoStart();
  }

  function onAuthFailed() {
    setSync('auth', 'Token rejected (invalid or revoked). Paste a new token or press Disconnect.');
  }

  // Offline at startup: reuse the saved list only if this exact token was already verified
  // for an account whose first merge completed. Otherwise stay blocked.
  function tryCachedAccount() {
    const b = store.get('tokenAcct', null), tok = getOverlayToken();
    if (b && typeof b === 'object' && tok && b.fp === tokenFp(tok) && /^\d{1,12}$/.test(String(b.id)) &&
        store.get('syncInit_' + b.id, false) === true) {
      enterAccount(String(b.id), b.name || '');
      sync.state = 'offline';
      maybeAutoStart();
    }
  }

  const unsyncedSet = (id) => new Set((store.get('unsynced_' + id, []) || []).map(String));

  // First sync for an account: merge local targets with the server list, losing nothing.
  async function initialMerge(id, serverList) {
    const owner = store.get('legacyOwner', null);
    const useLegacy = !owner || String(owner) === id;
    if (!owner) store.set('legacyOwner', id); // claim the old global list for this account only
    const local = new Map();
    if (useLegacy) legacyTargets().forEach(t => local.set(t.id, t));
    readTargets('targets_' + id).forEach(t => local.set(t.id, t)); // an already saved list wins
    const serverIds = new Set(serverList.map(s => s.id));
    const merged = new Map();
    for (const s of serverList) {
      const loc = local.get(s.id);
      merged.set(s.id, Object.assign(normTarget({ id: s.id }), loc || {}, { id: s.id, name: s.name || (loc && loc.name) || '' }));
    }
    const unsynced = unsyncedSet(id);
    let aborted = false, authFail = false, pushed = 0;
    for (const loc of local.values()) {
      if (serverIds.has(loc.id) || loc.id === id) continue; // own account can never be a target
      if (aborted) { merged.set(loc.id, loc); continue; }
      const r = await overlayRequest('POST', '/overlay/targets', { targetTornId: loc.id });
      if (isOk(r)) {
        pushed++;
        merged.set(loc.id, Object.assign({}, loc, { name: (r.data.target && r.data.target.name) || loc.name }));
        unsynced.delete(loc.id);
      } else if (r.status === 401) { aborted = true; authFail = true; merged.set(loc.id, loc); }
      else if (isTransient(r)) { aborted = true; merged.set(loc.id, loc); }
      else { merged.set(loc.id, loc); unsynced.add(loc.id); } // server refused: keep it, retry later
    }
    targets = [...merged.values()];
    store.set('unsynced_' + id, [...unsynced]);
    sync.unsynced = unsynced.size;
    saveTargets();
    clearLive(); targets.forEach(ensureLive);
    if (authFail) { onAuthFailed(); }
    else if (aborted) { setSync('offline', 'First merge interrupted — your targets are kept, retrying soon'); }
    else {
      store.set('syncInit_' + id, true);
      sync.retryUnsyncedAt = Date.now() + SYNC_RETRY_UNSYNCED;
      setSync('ok', 'Merged ' + targets.length + ' targets' + (pushed ? ' (' + pushed + ' sent to the site)' : ''));
    }
  }

  // Later syncs: the server list is the reference. Local-only targets are dropped (they were
  // deleted on the dashboard), except ones the server refused earlier (kept in `unsynced`).
  async function applyServer(serverList, reason) {
    const id = account.id;
    const unsynced = unsyncedSet(id);
    const serverIds = new Set(serverList.map(s => s.id));
    const prev = new Map(targets.map(t => [t.id, t]));
    for (const u of [...unsynced]) if (!prev.has(u) || serverIds.has(u)) unsynced.delete(u);

    if (unsynced.size && (reason === 'manual' || Date.now() >= sync.retryUnsyncedAt)) {
      sync.retryUnsyncedAt = Date.now() + SYNC_RETRY_UNSYNCED;
      for (const u of [...unsynced]) {
        const r = await overlayRequest('POST', '/overlay/targets', { targetTornId: u });
        if (isOk(r)) {
          unsynced.delete(u); serverIds.add(u);
          const name = (r.data.target && r.data.target.name) || '';
          if (!serverList.some(s => s.id === u)) serverList.push({ id: u, name });
        } else if (r.status === 401) { onAuthFailed(); return; }
        else if (isTransient(r)) break;
      }
    }

    const next = [];
    for (const s of serverList) {
      const old = prev.get(s.id);
      if (old) { if (!old.name) old.name = s.name; next.push(old); } // keep object identity: polls in flight stay valid
      else next.push(normTarget({ id: s.id, name: s.name }));
    }
    for (const t of targets) if (!serverIds.has(t.id) && unsynced.has(t.id)) next.push(t);

    const before = targets.map(t => t.id).join(','), after = next.map(t => t.id).join(',');
    targets = next;
    store.set('unsynced_' + id, [...unsynced]);
    sync.unsynced = unsynced.size;
    Object.keys(live).forEach(k => { if (!next.some(t => t.id === k)) delete live[k]; });
    targets.forEach(ensureLive);
    saveTargets();

    if (!targets.length && running) { stop(false, 'No targets left (removed on the site)'); autoResume = true; }
    else if (autoResume && targets.length) { autoResume = false; maybeAutoStart(); }
    setSync('ok', sync.unsynced ? sync.unsynced + ' target(s) not accepted by the server yet' : '');
    if (before !== after) render();
  }

  async function removeTarget(id) {
    if (!account) { // local-only mode, exactly like 2.5
      if (unverified()) return msg('Not connected to the sync server yet');
      dropLocal(id); return;
    }
    msg('Removing…');
    const r = await exclusive(() => overlayRequest('DELETE', '/overlay/targets', { targetTornId: id }));
    if (r.status === 401) { onAuthFailed(); return msg('Token rejected — target not removed'); }
    if (!isOk(r)) return msg(isTransient(r) ? 'Cannot reach the sync server — target not removed' : 'Server refused: ' + safeText(r.data && r.data.message));
    dropLocal(id);
    msg('Target removed');
  }
  function dropLocal(id) {
    targets = targets.filter(t => t.id !== id); delete live[id]; saveTargets();
    if (account) { const u = unsyncedSet(account.id); if (u.delete(id)) { store.set('unsynced_' + account.id, [...u]); sync.unsynced = u.size; } }
    if (!targets.length && running) stop(true);
    render();
  }

  async function onSyncClick() {
    const inp = $('#otk'), typed = inp.value.trim();
    if (typed) {
      if (!/^[a-f0-9]{64}$/i.test(typed)) return msg('That does not look like an overlay token (64 hex characters)');
      if (typed !== getOverlayToken()) { setOverlayToken(typed); store.set('tokenAcct', null); resetToUnverified(); }
      inp.value = '';
    }
    if (!getOverlayToken()) return msg('Paste your overlay token first');
    await syncNow('manual');
    maybeAutoStart();
    msg(sync.state === 'ok' ? 'Targets synced' : (sync.text || 'Sync did not complete'));
  }

  function disconnect() {
    if (!getOverlayToken()) return msg('No token saved');
    setOverlayToken(''); store.set('tokenAcct', null);
    if (running) stop(false);
    account = null; premium = null; clearLive(); autoResume = false; sync.unsynced = 0;
    targets = legacyTargets(); targets.forEach(ensureLive); // back to local-only mode
    setSync('off'); render(); maybeAutoStart();
    msg('Disconnected — local mode');
  }

  function renderSync() {
    let line;
    if (!getOverlayToken()) line = 'Sync: off (local list). Add an overlay token in Settings to share targets with the TornScope site.';
    else if (!account) line = sync.state === 'connecting' || sync.state === 'off' ? 'Sync: connecting…' : 'Sync: ' + (sync.text || 'not connected');
    else line = 'Sync: ' + (account.name || 'account') + ' [' + account.id + '] · ' +
      (sync.state === 'ok' ? 'synced ' + new Date(sync.at).toLocaleTimeString('en-GB') + (sync.text ? ' · ' + sync.text : '') : (sync.text || sync.state)) +
      (pendingEvents() ? ' · ' + pendingEvents() + ' event(s) waiting to be sent' : '');
    $('#syn').textContent = line;
    $('#sst').textContent = line;
  }

  /* ================= Interface (Shadow DOM) ================= */
  const CSS = `
  :host{all:initial}
  *{box-sizing:border-box}
  .hud{--cy:#16d9f2;--cy2:#67e8f9;--gold:#f5b72e;--ink:#3a2600;--mut:#8b97b0;--blip:#fff;
    position:fixed;z-index:99999;width:344px;font:12px/1.45 Inter,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;color:#eef2f9;
    background:rgba(10,15,29,.97);border:1px solid rgba(22,217,242,.22);border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,.55);overflow:hidden}
  .hd{display:flex;align-items:center;gap:5px;padding:9px 8px 9px 11px;cursor:move;user-select:none;-webkit-user-select:none;touch-action:none;border-bottom:1px solid rgba(255,255,255,.06)}
  .lg{width:24px;height:24px;color:var(--cy);flex:none;position:relative}
  .lg svg,.ci svg{width:100%;height:100%;display:block}
  .lg i{position:absolute;right:-2px;bottom:-1px;width:8px;height:8px;border-radius:50%;background:#5b6478;border:2px solid #0a0f1d}
  .lg i.on{background:#34d399}
  .nm{font-weight:700;font-size:13.5px;letter-spacing:-.01em;white-space:nowrap}.nm b{color:var(--cy)}
  .grow{flex:1;min-width:2px}
  .sum{display:none;color:#c7d0e2;font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:210px}
  .sum span{color:var(--mut);font-weight:500}
  a{color:inherit;text-decoration:none}
  .chip{display:inline-flex;align-items:center;gap:4px;padding:2px 8px 2px 5px;border-radius:999px;font-size:10.5px;flex:none;font-weight:700;white-space:nowrap;cursor:pointer}
  .chip .ci{width:14px;height:17px;color:var(--cy);flex:none}
  .chip.on{color:var(--gold);border:1px solid rgba(245,183,46,.55);background:linear-gradient(135deg,rgba(245,183,46,.22),rgba(245,183,46,.06))}
  .chip.off{background:var(--gold);color:var(--ink);padding-left:8px}.chip.off .ci{display:none}
  .ib{all:unset;box-sizing:border-box;cursor:pointer;width:24px;height:24px;display:grid;place-items:center;border-radius:8px;color:#cfd8ea;font-size:12px;background:rgba(255,255,255,.04);flex:none}
  .ib:hover{background:rgba(255,255,255,.12)}
  .ib.site{color:var(--cy2);background:rgba(22,217,242,.10)}
  .min{width:auto;min-width:0;border-radius:999px}
  .min .bd,.min .nm,.min #run,.min #site,.min .hd .grow{display:none}
  .min .hd{border-bottom:0;padding:7px 8px 7px 11px;gap:9px}
  .min .sum{display:inline}
  .min .chip.off{display:none!important}
  .min .chip{padding:0;border:0;background:none}.min .chip .pt{display:none}.min .chip .ci{width:16px;height:19px}
  .tabs{display:flex;gap:4px;padding:8px 10px 0}
  .tabs button{all:unset;cursor:pointer;flex:1;text-align:center;padding:6px 0;border-radius:9px;color:var(--mut);font-weight:600}
  .tabs button.on{background:rgba(22,217,242,.13);color:#fff}
  .pn{display:none;padding:9px 10px 6px;max-height:400px;overflow:auto}
  input[type=checkbox]{accent-color:#16d9f2}
  .bd[data-tab=s] .pnote{display:none!important}
  .pn.on{display:block}
  .card{position:relative;background:#131c31;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:9px 10px 9px 13px;margin-bottom:7px;overflow:hidden}
  .card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,#475569)}
  .card.flash{animation:fl 1s ease-in-out infinite;border-color:#fbbf24}
  @keyframes fl{50%{box-shadow:0 0 0 2px rgba(251,191,36,.55)}}
  .top{display:flex;align-items:center;gap:6px}
  .tn{font-weight:700;font-size:13px}
  .id{color:#6d7a93;font-size:10.5px}
  .st{margin-left:auto;padding:1px 9px;border-radius:999px;font-size:10.5px;font-weight:700;color:var(--c);background:rgba(255,255,255,.07);white-space:nowrap}
  .ln{margin-top:3px;color:#c7d0e2;font-size:12.5px}.ln i{font-style:normal;color:var(--mut)}
  .mt{margin-top:3px;color:#6d7a93;font-size:11px;display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px}
  .mt .v{color:#34d399}.mt .e{color:#fbbf24}
  .go{margin-left:auto;color:var(--cy2);font-weight:700;background:rgba(22,217,242,.10);border-radius:8px;padding:2px 8px;white-space:nowrap}
  .go:hover{background:rgba(22,217,242,.2)}
  .err{color:#f87171}
  .pb{height:5px;background:#222d45;border-radius:3px;margin-top:7px;overflow:hidden}
  .pb i{display:block;height:100%;background:linear-gradient(90deg,var(--cy),#38bdf8);border-radius:3px}
  .x{all:unset;cursor:pointer;color:#6d7a93;padding:0 3px;font-size:15px;line-height:1}
  .x:hover{color:#f87171}
  .add,.bar2{display:flex;gap:6px;margin-top:4px;flex-wrap:wrap}
  input[type=text],input[type=password],input[type=number],select{all:unset;box-sizing:border-box;flex:1;background:#0d1424;border:1px solid #233049;border-radius:9px;padding:7px 10px;color:#eef2f9;width:100%}
  input:focus,select:focus{border-color:var(--cy)}
  .card select{width:auto;flex:none;max-width:100%;padding:1px 5px;font-size:10.5px;color:#9fb0cf;border-radius:7px}
  button.pr{all:unset;box-sizing:border-box;cursor:pointer;background:var(--cy);color:#04202a;font-weight:700;padding:7px 14px;border-radius:9px;text-align:center}
  button.pr:hover{filter:brightness(1.1)}
  button.sc,a.sc{all:unset;box-sizing:border-box;cursor:pointer;background:rgba(22,217,242,.13);color:var(--cy2);font-weight:700;padding:7px 12px;border-radius:9px;text-align:center}
  button.sc:hover,a.sc:hover{background:rgba(22,217,242,.22)}
  button.dg{background:rgba(248,113,113,.12);color:#fca5a5}
  .hint{margin-top:6px;color:#6d7a93;font-size:10.5px}
  .tt{margin-top:6px;color:#6d7a93;font-size:10.5px;line-height:1.45}.tt div{margin:0 0 3px}.tt b{color:#9fb0cc;font-weight:600}.tt a{color:#67e8f9}.mob .tt{font-size:12px}
  .ft{display:flex;align-items:center;gap:7px;margin-top:9px;color:var(--mut);font-size:11px}
  .dot{width:7px;height:7px;border-radius:50%;background:#5b6478;flex:none}.dot.ok{background:#34d399;box-shadow:0 0 0 3px rgba(52,211,153,.15)}.dot.warn{background:#fbbf24}.dot.bad{background:#f87171}
  .pnote{display:none;align-items:center;gap:8px;margin:2px 10px 9px;padding:7px 10px;border-radius:10px;font-size:11.5px}
  .pnote .ci{width:16px;height:19px;color:var(--cy);flex:none}
  .pnote.up{display:flex;border:1px solid rgba(245,183,46,.35);background:rgba(245,183,46,.07);color:#f3d58a}
  .pnote.ok{display:flex;color:var(--gold);padding-left:2px}
  .pnote a{margin-left:auto;color:var(--gold);font-weight:700;white-space:nowrap}
  .pnote .nx{all:unset;cursor:pointer;color:#a8895a;padding:0 2px}
  .grp{margin-bottom:12px}
  .grp h4{margin:0 0 6px;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
  label{display:block;margin-bottom:8px;color:var(--mut)}
  label input[type=text],label input[type=password],label input[type=number]{margin-top:3px;display:block}
  label.ck{display:flex;align-items:center;gap:7px;color:#dbe3f2;padding:3px 0}
  .gw{display:flex;align-items:center;gap:6px;font-size:10.5px;color:var(--mut);margin-top:4px}
  .gb{width:70px;height:5px;background:#222d45;border-radius:3px;overflow:hidden}
  .gb i{display:block;height:100%;width:0;background:#34d399;transition:width .3s}
  .alarm{display:none;margin:8px 10px 0;border-radius:11px;overflow:hidden;background:linear-gradient(90deg,#991b1b,#dc2626);color:#fff;animation:fl2 .8s ease-in-out infinite}
  @keyframes fl2{50%{filter:brightness(1.25)}}
  .alarm.on{display:block}
  .alarm button{all:unset;cursor:pointer;display:block;width:100%;box-sizing:border-box;padding:9px 10px 5px;text-align:center;font-weight:700}
  .alarm a{display:block;margin:0 8px 8px;padding:6px;border-radius:8px;text-align:center;font-weight:700;background:rgba(255,255,255,.18);cursor:pointer}
  .alarm a:hover{background:rgba(255,255,255,.28)}
  .min .alarm{margin:0 8px 8px;border-radius:14px}
  .msg{padding:0 12px 9px;color:#fbbf24;min-height:6px;font-size:11px}
  .empty{color:#6d7a93;text-align:center;padding:14px 0}
  .hud.ring .hd{background:linear-gradient(90deg,rgba(127,29,29,.55),rgba(220,38,38,.25))}
  .hud.mob{width:min(calc(100vw - 16px),392px);font-size:14px}
  .mob.min{width:auto}
  .mob .ib{width:36px;height:36px;font-size:16px}
  .mob .tabs button{padding:11px 0}
  .mob .pn{max-height:calc(100vh - 250px);max-height:calc(100dvh - 250px)}
  .mob input[type=text],.mob input[type=password],.mob input[type=number],.mob select{font-size:16px;padding:11px 10px}
  .mob .card select{font-size:13px;padding:5px 8px}
  .mob button.pr,.mob button.sc,.mob a.sc{padding:11px 14px}
  .mob .x{padding:6px 10px;font-size:22px}
  .mob .mt,.mob .ft,.mob .hint,.mob .pnote{font-size:12.5px}.mob .id,.mob .st{font-size:12px}
  .mob .tn{font-size:14.5px}.mob .ln{font-size:13.5px}.mob .go{padding:6px 12px}
  .mob .alarm button{padding:14px 10px 8px;font-size:15px}.mob .alarm a{padding:11px}
  `;

  const host = document.createElement('div');
  host.id = 'ttw-host';
  (document.body || document.documentElement).appendChild(host);
  const root = host.attachShadow({ mode: 'open' });
  root.innerHTML = `<style>${CSS}</style>
  <div class="hud" id="hud">
    <div class="hd" id="hd">
      <span class="lg">${LOGO}<i id="dot"></i></span><span class="nm">Torn<b>Scope</b></span><span class="sum" id="sum"></span><span class="grow"></span>
      <a class="chip" id="prem" target="_blank" rel="noopener noreferrer" style="display:none"><span class="ci">${CROWN}</span><span class="pt" id="premt"></span></a>
      <a class="ib site" id="site" target="_blank" rel="noopener noreferrer" title="Open TornScope">↗</a>
      <button class="ib" id="run" title="Start / stop">▶</button>
      <button class="ib" id="mn" title="Minimize">–</button>
    </div>
    <div class="alarm" id="alarm">
      <button id="alm"></button>
      <a id="almgo" href="${TRAVEL_URL}">✈ Open Travel ↗</a>
    </div>
    <div class="bd">
      <nav class="tabs">
        <button data-tab="t" class="on">Targets</button><button data-tab="w">⚔ War</button><button data-tab="s">Settings</button>
      </nav>
      <section class="pn on" id="p-t">
        <div class="hint" id="wban" style="display:none;color:#fbbf24;margin:0 0 6px"></div>
        <div id="cards"></div>
        <div class="add"><input type="text" id="nid" placeholder="Player ID" inputmode="numeric"><button class="pr" id="addb">Add</button></div>
        <div class="ft"><span class="dot" id="sdot"></span><span id="syn"></span></div>
        <div class="hint" id="cap"></div>
      </section>
      <section class="pn" id="p-w">
        <label class="ck"><input type="checkbox" id="won"> War mode <span class="hint" style="display:inline">(pauses normal targets)</span></label>
        <label>Enemy faction ID<input type="text" id="wfid" placeholder="Faction ID" inputmode="numeric"></label>
        <div class="bar2"><button class="pr" id="wsync">Sync</button><button class="sc" id="wfind">Find my enemy</button></div>
        <label>Your aircraft<select id="wplane"></select></label>
        <label class="ck"><input type="checkbox" id="wall"> Show everyone</label>
        <div class="hint" id="wsum" style="margin:6px 0"></div>
        <div class="hint" id="wsave" style="display:none"></div>
        <div id="wlist"></div>
        <div class="hint" id="wfeed" style="margin-top:6px"></div>
        <div class="hint" id="wst"></div>
        <div class="hint">One request reads the whole faction (3 per minute). Sync replaces the list. The aircraft is read from Torn; the landing is calculated from the take-off, so it needs the take-off to be seen (Premium also fills it in from the server).</div>
      </section>
      <section class="pn" id="p-s">
        <div class="grp"><h4>Torn</h4>
          <label>API key (Public access level)<input type="password" id="key" placeholder="API key"></label>
          <div class="tt"><div><b>Key storage:</b> Your key stays in this browser or Torn PDA and is sent only to api.torn.com, never to our server.</div><div><b>Data stored:</b> Only if you link a TornScope account: your watched players and the status changes seen for them.</div><div><b>Shared:</b> Never sold, published or given to third parties.</div><div><b>Purpose:</b> Alerts and history for your targets. Public access level is enough.</div><div><b>War mode:</b> reads the public member list of the enemy faction you choose, only from api.torn.com.</div><a id="terms" target="_blank" rel="noopener noreferrer">Full details ↗</a></div></div>
        <div class="grp"><h4>TornScope account</h4>
          <div class="hint" id="sst" style="margin:0 0 6px"></div>
          <label>Overlay token<input type="password" id="otk" placeholder="Paste the token from the site" autocomplete="off" spellcheck="false"></label>
          <div class="bar2"><button class="pr" id="sync">Sync targets</button><a class="sc" id="site2" target="_blank" rel="noopener noreferrer">Open site ↗</a><button class="sc dg" id="otkx">Disconnect</button></div>
          <div class="hint" id="sprem" style="margin-top:8px"></div></div>
        <div class="grp"><h4>Alerts</h4>
          <label class="ck"><input type="checkbox" id="snd"> Alert sound</label>
          <label class="ck"><input type="checkbox" id="ntf"> Notification</label>
          <label>Fast check interval (seconds, min 3)<input type="number" id="fast" min="3" max="30"></label>
          <div class="bar2"><button class="sc" id="tst">Test alert</button><button class="sc" id="dk">Move panel top / bottom</button></div>
          <div class="hint">The alarm repeats until you stop it. Monitoring continues afterward.</div></div>
        <div class="gw" title="API requests over the last 60 seconds">API usage <span class="gb"><i id="gf"></i></span><span id="gt">0/${API_CAP}</span> per min · v${VERSION}</div>
        <div class="hint" id="sh"></div>
        <div class="hint">Developer: Zeussh · Torn ID 4268037</div>
      </section>
      <div class="pnote" id="pnote"></div>
      <div class="msg" id="msg"></div>
    </div>
  </div>`;

  const $ = (s) => root.querySelector(s);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtDur = (s) => { s = Math.max(0, Math.round(s)); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(x).padStart(2, '0'); };
  const hhmm = (sec) => new Date(sec * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  let msgTimer;
  function msg(t) { $('#msg').textContent = t; clearTimeout(msgTimer); msgTimer = setTimeout(() => { $('#msg').textContent = ''; }, 5000); }


  /* ================= War mode (enemy faction roster) ================= */
  // One request returns the whole enemy faction (status, travel, last action): no per-member scanning.
  // While War mode is on, normal target tracking is paused so the request budget (API_CAP) is never exceeded.
  const WAR_EVERY = 20000;           // ms between roster reads (3 requests / minute)
  const W = (() => {
    const s = store.get('war', null) || {};
    return { on: !!s.on, fid: /^\d{1,8}$/.test(String(s.fid || '')) ? String(s.fid) : '', plane: PLANES.some(([n]) => n === s.plane) ? s.plane : 'Airstrip',
      all: !!s.all, learn: (s.learn && typeof s.learn === 'object') ? s.learn : {}, members: (s.members && typeof s.members === 'object') ? s.members : {}, name: s.name || '', pollAt: Number(s.pollAt) || 0,
      nextAt: 0, busy: false, err: '', feed: [], lastBeep: 0, srvAt: 0 };
  })();
  const warOn = () => W.on;
  const warSave = () => { const ids = Object.keys(W.learn); if (ids.length > 600) ids.slice(0, ids.length - 600).forEach(k => { delete W.learn[k]; }); store.set('war', { on: W.on, fid: W.fid, plane: W.plane, all: W.all, learn: W.learn, members: W.members, name: W.name, pollAt: W.pollAt }); };

  // Torn gives no landing time for travellers (status.until is 0). The aircraft comes from plane_image_type,
  // the take-off is the middle of the window between two reads, and the landing is calculated from them.
  const PTYPE = { airliner: 'Standard', light_aircraft: 'Airstrip' };   // other values are shown as they are
  const planeFactor = (name) => (PLANES.find(([n]) => n === name) || [0, 0])[1];
  // Duration in seconds, or 0 when unknown. book: true / false / null (unknown)
  function warDur(plane, country, book) {
    const base = BASE_MIN[country], f = planeFactor(book ? plane + '+book' : plane);
    return base && f ? Math.round(base * f * 60) : 0;
  }
  // Best landing estimate: { at, alt } (alt = earlier landing if the flight was booked) or null
  function warLand(m) {
    if (!(m.takeoff > 0) || !PTYPE[m.ptype]) return null;
    const plane = PTYPE[m.ptype], learnt = W.learn[m.id];
    const d0 = warDur(plane, m.country, false), d1 = warDur(plane, m.country, true);
    if (!d0) return null;
    if (learnt === 1 && d1) return { at: m.takeoff + d1, alt: 0 };
    if (learnt === 0 || !d1) return { at: m.takeoff + d0, alt: 0 };
    return { at: m.takeoff + d0, alt: m.takeoff + d1 };
  }

  // Enemy faction of a faction: ranked war first, then territory / raid wars (same logic as the server).
  function warPick(data, myFid, nowSec) {
    const list = [];
    const add = (id, name, kind, start, end) => {
      const fid = String(id == null ? '' : id);
      if (!/^\d+$/.test(fid) || fid === '0' || fid === String(myFid)) return;
      if (list.some(x => x.id === fid && x.kind === kind)) return;
      list.push({ id: fid, name: typeof name === 'string' ? name.slice(0, 40) : '', kind, start: Number(start) || 0, end: Number(end) || 0 });
    };
    const objs = (v) => (v && typeof v === 'object') ? Object.values(v) : [];
    objs(data && data.ranked_wars).forEach(w => { if (!w || typeof w !== 'object') return; const info = w.war || {};
      Object.entries(w.factions || {}).forEach(([fid, f]) => add(fid, f && f.name, 'ranked', info.start, info.end)); });
    objs(data && data.territory_wars).forEach(w => { if (!w || typeof w !== 'object') return;
      add(w.assaulting_faction, w.assaulting_faction_name, 'territory', w.started || w.start, w.ends || w.end);
      add(w.defending_faction, w.defending_faction_name, 'territory', w.started || w.start, w.ends || w.end); });
    objs(data && data.raid_wars).forEach(w => { if (!w || typeof w !== 'object') return;
      add(w.aggressor_faction, w.aggressor_faction_name, 'raid', w.start || w.started, w.end || w.ends);
      add(w.defender_faction, w.defender_faction_name, 'raid', w.start || w.started, w.end || w.ends); });
    const rank = { ranked: 0, territory: 1, raid: 2 };
    const act = list.filter(x => !x.end || x.end > nowSec).sort((a, b) => rank[a.kind] - rank[b.kind] || b.start - a.start);
    return act[0] || null;
  }

  // One Torn API call (counts in the 90 / minute budget). Resolves { data } or { error }.
  async function warGet(path, extra) {
    reqLog.push(Date.now());
    const url = `https://api.torn.com/${path}?${extra}&key=${encodeURIComponent(getApiKey())}&comment=TravelWatcher`;
    try {
      let d;
      if (isPDA()) {
        const r = await window.PDA_httpGet(url);
        if (!r || (r.status && (r.status < 200 || r.status >= 300))) return { error: 'PDA HTTP error' };
        d = JSON.parse(r.responseText || '{}');
      } else {
        const r = await fetch(url); if (!r.ok) return { error: 'HTTP ' + r.status };
        d = await r.json();
      }
      if (d && d.error) { if ([2, 10, 13, 18].includes(d.error.code)) { stop(true, 'API key invalid or disabled'); } return { error: `API ${d.error.code}: ${d.error.error}`, code: d.error.code }; }
      return { data: d };
    } catch (e) { return { error: 'Network/PDA error' }; }
  }

  function warMember(id, m, now) {
    const st = (m && m.status) || {}, la = (m && m.last_action) || {};
    const desc = typeof st.description === 'string' ? st.description : '';
    const ret = isReturn(desc);
    return { id: String(id), name: String(m && m.name || '').slice(0, 40), level: Math.max(0, Math.floor(Number(m && m.level) || 0)),
      state: String(st.state || '').slice(0, 24), desc: desc.slice(0, 120), until: Math.max(0, Math.floor(Number(st.until) || 0)),
      la: Math.max(0, Math.floor(Number(la.timestamp) || 0)), country: destOf(desc) || '', ret,
      ptype: String(st.plane_image_type || '').slice(0, 24), takeoff: 0, hosp: 0 };
  }

  function warAlert(text) {
    W.feed.unshift({ at: Date.now(), text }); W.feed.length = Math.min(W.feed.length, 12);
    const c = cfg();
    if (c.sound && Date.now() - W.lastBeep > 3000) { W.lastBeep = Date.now(); beep(); }  // one beep, never a looping alarm
    if (c.notif) notify('TornScope · War', text);
  }

  // Replace the roster with a fresh read. Alerts only for changes seen between two reads (never on the first read).
  function warApply(data, replace) {
    const raw = data && data.members;
    const entries = Array.isArray(raw) ? raw.map(m => [m && m.id, m]) : (raw && typeof raw === 'object') ? Object.entries(raw) : [];
    if (!entries.length) { W.err = 'No members in the answer'; return false; }
    const now = Math.floor(Date.now() / 1000), prevAt = W.pollAt, old = W.members, had = Object.keys(old).length > 0 && !replace, next = {};
    for (const [id, m] of entries) {
      if (!/^\d+$/.test(String(id)) || !m) continue;
      const n = warMember(id, m, now), p = old[id];
      if (p && n.state === 'Traveling' && p.state === 'Traveling' && p.desc === n.desc) n.takeoff = p.takeoff;                  // same flight
      else if (p && n.state === 'Traveling' && p.state !== 'Traveling' && prevAt) n.takeoff = Math.round((prevAt + now) / 2);    // take-off seen between two reads
      // landed: compare the real flight time with the two possible durations (booked or not) and remember it for this player
      if (p && p.state === 'Traveling' && n.state !== 'Traveling' && p.takeoff > 0 && PTYPE[p.ptype]) {
        const obs = now - p.takeoff, d0 = warDur(PTYPE[p.ptype], p.country, false), d1 = warDur(PTYPE[p.ptype], p.country, true);
        if (d0 && d1 && obs >= d1 - 60 && obs <= d0 + 120) W.learn[id] = Math.abs(obs - d1) < Math.abs(obs - d0) ? 1 : 0;
      }
      if (p && n.state === 'Hospital' && p.state === 'Hospital' && p.until === n.until) n.hosp = p.hosp;
      if (had && p && p.state !== 'Traveling' && n.state === 'Traveling') {
        const L = (n.takeoff > 0 && !n.ret) ? warLand(n) : null, pl = PTYPE[n.ptype] ? ' · ' + PTYPE[n.ptype] : (n.ptype ? ' · ' + n.ptype : '');
        const when = L ? ', lands ~' + hhmm(L.at) : '';
        warAlert(n.ret ? `${n.name || id} is returning to Torn${when}${pl}` : `${n.name || id} takes off → ${n.country || 'abroad'}${when}${pl}`);
      }
      next[id] = n;
    }
    W.members = next; W.pollAt = now; W.err = '';
    warSave(); return true;
  }

  // Server side data (Premium): take-offs seen while this browser was closed.
  async function warServerMerge() {
    if (!getOverlayToken() || !W.fid) return;
    const r = await overlayRequest('GET', '/overlay/war');
    if (!isOk(r) || !Array.isArray(r.data.members)) return;
    for (const s of r.data.members) {
      const m = W.members[String(s.id)];
      if (m && m.state === 'Traveling' && !(m.takeoff > 0) && Number(s.takeoffAt) > 0 && s.description === m.desc) m.takeoff = Number(s.takeoffAt);
    }
  }
  function warPushConfig() {
    if (!getOverlayToken()) return;
    overlayRequest('PUT', '/overlay/war', { factionId: Number(W.fid) || 0, enabled: W.on && !!W.fid }).then(() => {}, () => {});
  }

  async function warPoll(manual) {
    if (W.busy || !W.fid) return;
    if (!getApiKey()) { W.err = 'Enter your API key in Settings'; showTab('s'); return; }
    W.busy = true;
    try {
      const r = await warGet('faction/' + W.fid, `selections=basic&timestamp=${Math.floor(Date.now() / 1000)}`);
      if (r.data) {
        if (warApply(r.data, !!manual)) { W.name = String(r.data.name || W.name || '').slice(0, 40); warSave(); if (Date.now() - W.srvAt > 60000) { W.srvAt = Date.now(); warServerMerge().then(() => {}, () => {}); } }
        W.nextAt = Date.now() + WAR_EVERY;
      } else { W.err = r.error; W.nextAt = Date.now() + (r.code === 5 || r.code === 8 ? 60000 : 30000); }
    } finally { W.busy = false; render(); }
  }

  // Called every second by the engine while War mode is on (instead of the normal targets).
  function warTick(now) {
    if (W.fid && !W.busy && now >= W.nextAt && reqLog.length < API_CAP) { W.nextAt = now + WAR_EVERY; warPoll(false); }
    const sec = now / 1000;
    for (const id in W.members) {
      const m = W.members[id];
      if (m.state === 'Hospital' && m.until > sec && m.until - sec <= 60 && m.hosp !== m.until) {
        m.hosp = m.until; warAlert(`${m.name || id} leaves hospital in ${Math.round(m.until - sec)} s`);
      }
    }
  }

  async function warFind() {
    if (!getApiKey()) { msg('Enter your API key in Settings'); showTab('s'); return; }
    msg('Looking for your enemy…');
    const me = await warGet('user/', 'selections=profile');
    const myFid = me.data && me.data.faction ? Math.floor(Number(me.data.faction.faction_id) || 0) : 0;
    if (!me.data) return msg('Could not read your profile: ' + me.error);
    if (!myFid) return msg('You are not in a faction. Enter the enemy ID by hand.');
    const mine = await warGet('faction/' + myFid, 'selections=basic');
    if (!mine.data) return msg('Could not read your faction: ' + mine.error);
    const best = warPick(mine.data, myFid, Math.floor(Date.now() / 1000));
    if (!best) return msg('No war found for your faction. Enter the enemy ID by hand.');
    W.fid = best.id; W.name = best.name; $('#wfid').value = W.fid; warSave(); warPushConfig();
    msg(`Enemy found: ${best.name || best.id} (${best.kind} war). Press Sync.`);
    render();
  }

  function warSyncClick() {
    const v = ($('#wfid').value || '').trim();
    if (!/^\d{1,8}$/.test(v)) return msg('Enter the enemy faction ID (digits only)');
    if (v !== W.fid) { W.fid = v; W.name = ''; W.members = {}; W.pollAt = 0; }
    warSave(); warPushConfig(); msg('Reading the enemy faction…');
    warPoll(true);
  }
  function warToggle(on) {
    W.on = !!on; warSave(); warPushConfig();
    if (W.on) { W.nextAt = 0; msg(W.fid ? (running ? 'War mode on: normal tracking paused' : 'War mode on. Press ▶ to follow the enemy') : 'War mode on. Enter the enemy faction ID, then Sync'); }
    else msg('War mode off: normal tracking resumes');
    render();
  }

  const WAR_COLORS = { Traveling: '#16d9f2', Abroad: '#60a5fa', Hospital: '#f87171', Okay: '#34d399' };
  const ago = (sec) => { const s = Math.max(0, Date.now() / 1000 - sec); return s < 90 ? 'now' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 129600 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; };
  const myFlight = (country) => { const f = (PLANES.find(([n]) => n === W.plane) || [0, 1])[1]; return BASE_MIN[country] ? Math.round(BASE_MIN[country] * f * 60) : 0; };

  // Replace an element's HTML without flicker or scroll jump: skip identical markup, freeze the height, restore scroll positions.
  function setHTML(el, html) {
    if (el._h === html) return;
    el._h = html;
    const saved = [];
    for (let n = el; n; n = n.parentElement) if (n.scrollTop) saved.push([n, n.scrollTop]);
    el.style.minHeight = el.offsetHeight + 'px';
    el.innerHTML = html;
    saved.forEach(([n, t]) => { n.scrollTop = t; });
    el.style.minHeight = '';
    saved.forEach(([n, t]) => { if (n.scrollTop !== t) n.scrollTop = t; });
  }

  function renderWar() {
    if (!$('#p-w')) return;
    const ban = $('#wban'); ban.style.display = W.on ? 'block' : 'none';
    ban.textContent = W.on ? '⚔ War mode is on: normal targets are paused. Open the War tab.' : '';
    $('#wsave').textContent = '';
    if (!$('#p-w').classList.contains('on')) return;
    const list = Object.values(W.members), sec = Date.now() / 1000;
    const cnt = (s) => list.filter(m => m.state === s).length;
    $('#wsum').textContent = list.length ? `${W.name ? W.name + ' · ' : ''}${list.length} members · ✈ ${cnt('Traveling')} · abroad ${cnt('Abroad')} · hospital ${cnt('Hospital')}` : 'No list yet. Enter the enemy faction ID and press Sync.';
    setHTML($('#wst'), W.err ? `<span class="err">${esc(W.err)}</span>` : (W.pollAt ? `Updated ${hhmm(W.pollAt)} · every ${WAR_EVERY / 1000} s${running ? '' : ' · paused (press ▶)'}` : ''));
    const etaOf = (m) => { if (m.state === 'Traveling') { const L = warLand(m); return L ? L.at : 9e12; } return m.until || 9e12; };
    const rank = (m) => m.state === 'Traveling' ? 0 : m.state === 'Hospital' ? 1 : m.state === 'Abroad' ? 2 : 3;
    const shown = list.filter(m => W.all || rank(m) < 3).sort((a, b) => rank(a) - rank(b) || (rank(a) < 2 ? etaOf(a) - etaOf(b) : (b.la - a.la)));
    setHTML($('#wlist'), shown.map(m => {
      const c = WAR_COLORS[m.state] || '#64748b';
      let line = '', gap = '';
      if (m.state === 'Traveling') {
        const L = warLand(m), left = L ? L.at - sec : 0, planeTxt = PTYPE[m.ptype] ? '✈ ' + esc(PTYPE[m.ptype]) : m.ptype ? '✈ ' + esc(m.ptype) : '<i>aircraft unknown</i>';
        const lands = L ? (left > 0 ? `lands ~${esc(hhmm(L.at))} (in ${fmtDur(left)})` + (L.alt ? ` · ~${esc(hhmm(L.alt))} if booked` : '') : 'about to land') : 'landing unknown (seen mid-flight)';
        line = `${m.ret ? '← Torn' : '→ ' + esc(m.country || m.desc || 'abroad')} <i>· ${lands}</i> · ${planeTxt}`;
        const mine = !m.ret && m.country ? myFlight(m.country) : 0;
        if (mine && L && left > 0) {
          const diff = L.at - (sec + mine), leaveIn = L.at - mine - sec;
          gap = `Leave now (${esc(W.plane)}): you land <b class="${diff >= 0 ? 'v' : 'e'}">${fmtDur(Math.abs(diff))} ${diff >= 0 ? 'before' : 'after'}</b> him · ${leaveIn > 0 ? 'leave in <b class="v">' + fmtDur(leaveIn) + '</b> to land together' : 'too late to land together'}`;
        }
      } else if (m.state === 'Hospital') line = m.until > sec ? `Hospital <i>· out in ${fmtDur(m.until - sec)}</i>` : 'Hospital <i>· out</i>';
      else line = esc(m.desc || m.state || '—');
      return `<div class="card" style="--c:${c}"><div class="top"><span class="tn">${esc(m.name || m.id)}</span><span class="id">[${esc(m.id)}] L${m.level}</span><span class="st">${esc(m.state === 'Traveling' ? '✈ Traveling' : m.state || '—')}</span></div>` +
        `<div class="ln">${line}</div><div class="mt"><span>active ${esc(ago(m.la))}</span>${gap ? '<span>' + gap + '</span>' : ''}<a class="go" href="https://www.torn.com/profiles.php?XID=${esc(m.id)}" target="_blank" rel="noopener noreferrer">Profile ↗</a></div></div>`;
    }).join('') || (list.length ? '<div class="empty">Nobody is moving. Tick “Show everyone” to see the whole list.</div>' : ''));
    setHTML($('#wfeed'), W.feed.map(f => `<div><i>${esc(new Date(f.at).toLocaleTimeString('en-GB'))}</i> ${esc(f.text)}</div>`).join(''));
  }

  function showTab(k) {
    root.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === k));
    root.querySelectorAll('.pn').forEach(p => p.classList.toggle('on', p.id === 'p-' + k));
    $('.bd').dataset.tab = k;
  }

  const MODES = { fast: () => `⚡ ${cfg().fast} s`, slow: () => '60 s', pause: () => 'paused until landing', abroad: () => '20 s', other: () => '30 s' };
  const COLORS = { Okay: '#34d399', Traveling: '#16d9f2', Abroad: '#60a5fa', Hospital: '#f87171', Jail: '#f87171' };
  function chip(L) {
    if (L.state === 'Okay') return 'Okay';
    if (L.state === 'Traveling') return '✈ Traveling';
    if (L.state === 'Abroad') return 'Abroad';
    if (L.state === 'Hospital' || L.state === 'Jail') return L.state;
    return L.state || '—';
  }

  function renderCards() {
    const c = $('#cards'), now = Date.now();
    if (!targets.length) {
      const msgText = unverified()
        ? (sync.state === 'auth' ? 'Overlay token rejected.<br>Open Settings to fix it or Disconnect.' : 'Waiting for the sync server…')
        : 'No targets.<br>Add a player ID below.';
      setHTML(c, '<div class="empty">' + msgText + '</div>'); return;
    }
    setHTML(c, targets.map(t => {
      const L = ensureLive(t), fl = L.flash > now, dest = destOf(L.desc), ret = isReturn(L.desc);
      let line, prog = '';
      if (L.state === 'Traveling') {
        const where = dest || L.desc || 'unknown destination';
        line = (ret ? '← ' : '→ ') + esc(where);
        if (L.until) {
          const left = L.until - now / 1000;
          line += ` <i>· lands ${esc(hhmm(L.until))} (in ${fmtDur(left)})</i>`;
          let t0 = L.t0;
          if (!t0 && BASE_MIN[dest]) { const f = (PLANES.find(([n]) => n === (t.plane || 'Airstrip')) || [0, 1])[1]; t0 = L.until * 1000 - BASE_MIN[dest] * f * 60000; }
          if (t0 && L.until * 1000 > t0) prog = `<div class="pb"><i style="width:${Math.min(100, Math.max(0, (now - t0) / (L.until * 1000 - t0) * 100)).toFixed(1)}%"></i></div>`;
        } else line += ' <i>· landing time unknown</i>';
      } else if (L.state === 'Abroad') line = 'In ' + esc(dest || L.desc.replace(/^In /i, ''));
      else line = esc(L.desc || '—');
      const src = L.state === 'Traveling' && L.until ? (L.untilSrc === 'api' ? '<span class="v">✓ Torn</span>' : '<span class="e">≈ est.</span>') : '';
      const info = L.err ? `<span class="err">${esc(L.err)}</span>`
        : (running && L.seen ? `last action ${esc(L.rel || '?')} · ${MODES[L.mode] ? MODES[L.mode]() : '—'}` : (running ? 'first check…' : 'paused'));
      const plane = `<select data-plane="${esc(t.id)}" title="Aircraft used to estimate this player's flights" aria-label="Aircraft for ${esc(t.name || t.id)}">
            ${PLANES.map(([name]) => `<option value="${esc(name)}"${(t.plane || 'Airstrip') === name ? ' selected' : ''}>✈ ${esc(name)}</option>`).join('')}</select>`;
      const go = (L.state === 'Traveling' || L.state === 'Abroad') ? `<a class="go" href="${TRAVEL_URL}" title="Open Torn's travel page">Travel ↗</a>` : '';
      return `<div class="card${fl ? ' flash' : ''}" style="--c:${COLORS[L.state] || '#64748b'}">
        <div class="top"><span class="tn">${esc(t.name || 'Player')}</span><span class="id">[${esc(t.id)}]</span>
          <span class="st">${esc(chip(L))}</span><button class="x" data-rm="${esc(t.id)}" title="Remove">×</button></div>
        <div class="ln">${line}</div>${prog}
        <div class="mt">${src}<span>${info}</span>${plane}${go}</div></div>`;
    }).join(''));
  }

  function premiumState() {
    if (!premium) return null;
    const left = premium.until - Date.now() / 1000;
    return { active: premium.admin || left > 0, admin: premium.admin, left };
  }
  const todayKey = () => new Date().toISOString().slice(0, 10);

  function renderHeader() {
    const n = reqLog.filter(t => Date.now() - t < 60000).length;
    $('#gt').textContent = `${n}/${API_CAP}`;
    $('#gf').style.width = Math.min(100, n / API_CAP * 100) + '%';
    $('#gf').style.background = n > API_CAP * 0.85 ? '#f87171' : n > API_CAP * 0.6 ? '#fbbf24' : '#34d399';
    $('#dot').classList.toggle('on', running);
    const al = alarmOn();
    $('#alarm').classList.toggle('on', al);
    $('#hud').classList.toggle('ring', al);
    if (al) $('#alm').textContent = '🔔 ' + (alarmInfo.name || 'A target') + ' is flying' + (alarmInfo.dest ? ' to ' + alarmInfo.dest : '') + ' — tap to stop';

    const flyingList = targets.filter(t => live[t.id] && live[t.id].state === 'Traveling');
    const nextLand = flyingList.map(t => live[t.id].until).filter(Boolean).sort((a, b) => a - b)[0];
    $('#sum').innerHTML = al ? esc(alarmInfo.name || 'Alarm') + ' <span>is flying — tap</span>'
      : !running ? 'paused'
      : flyingList.length ? `${flyingList.length} flying` + (nextLand ? ` <span>· next lands ${esc(hhmm(nextLand))}</span>` : '')
      : `${targets.length} target${targets.length === 1 ? '' : 's'} <span>· all quiet</span>`;
    $('#run').textContent = running ? '⏸' : '▶';
    $('#mn').textContent = $('#hud').classList.contains('min') ? '▾' : '–';
    const f = cfg().fast, worst = Math.ceil(targets.length * 60 / f);
    $('#cap').textContent = `${targets.length}/${maxTargets()} targets · max load ≈ ${worst} req/min (cap ${API_CAP})`;

    // site + Premium
    const base = siteBase || WORKER_URL;
    $('#site').href = base + '/dashboard'; $('#site2').href = base + '/dashboard'; $('#terms').href = base + '/terms';
    const pc = $('#prem'), ps = premiumState(), pn = $('#pnote');
    pc.href = base + '/dashboard#/premium';
    if (!account || !ps) { pc.style.display = 'none'; pn.className = 'pnote'; $('#sprem').textContent = account ? 'Premium: status unknown (not synced yet).' : ''; return; }
    pc.style.display = '';
    if (ps.active) {
      const t = ps.admin ? 'Premium' : (ps.left >= 86400 ? 'Premium · ' + Math.ceil(ps.left / 86400) + ' d' : 'Premium · ' + Math.max(1, Math.ceil(ps.left / 3600)) + ' h');
      pc.className = 'chip on'; $('#premt').textContent = t;
      pn.className = 'pnote ok'; pn.innerHTML = `<span class="ci">${CROWN}</span>Server tracking is on: your targets keep being recorded when TornScope is closed.`;
      $('#sprem').textContent = ps.admin ? 'Premium: administrator account.' : 'Premium active until ' + new Date(premium.until * 1000).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) + '.';
    } else {
      pc.className = 'chip off'; $('#premt').textContent = '♛ Go Premium';
      const hidden = store.get('pdis', '') === todayKey();
      pn.className = hidden ? 'pnote' : 'pnote up';
      pn.innerHTML = `<span class="ci">${CROWN}</span><span>Tracking only works while TornScope is open.</span><a href="${esc(base)}/dashboard#/premium" target="_blank" rel="noopener noreferrer">Get Premium ↗</a><button class="nx" id="pdis" title="Hide for today">×</button>`;
      $('#sprem').textContent = 'Premium: not active. Tracking works only while this page is open.';
    }
  }

  function render() {
    renderHeader(); renderSync(); renderWar();
    const dotEl = $('#sdot');
    dotEl.className = 'dot ' + (sync.state === 'ok' ? 'ok' : (sync.state === 'offline' || sync.state === 'connecting') ? 'warn' : (sync.state === 'auth' || sync.state === 'error') ? 'bad' : '');
    // Rebuilding the cards every second closes an open aircraft dropdown on mobile.
    const active = root.getRootNode().activeElement || document.activeElement;
    if (!(active && active.matches && active.matches('select[data-plane]'))) renderCards();
  }

  /* ----- Events ----- */
  root.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (a && a.id === 'almgo') { setTimeout(stopAlarm, 0); return; } // the link opens Torn's travel page in this same tab and also stops the alarm
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.tab) return showTab(b.dataset.tab);
    if (b.dataset.rm) { removeTarget(b.dataset.rm); return; }
    if (b.id === 'sync') { onSyncClick(); return; }
    if (b.id === 'otkx') { disconnect(); return; }
    if (b.id === 'dk') return flipDock();
    if (b.id === 'pdis') { store.set('pdis', todayKey()); return render(); }
    if (b.id === 'alm') { stopAlarm(); return msg('Alarm stopped; monitoring continues'); }
    if (b.id === 'run') return running ? stop(true) : start();
    if (b.id === 'mn') { const m = $('#hud').classList.toggle('min'); store.set('min', m); return; }
    if (b.id === 'addb') return addTarget();
    if (b.id === 'wsync') return warSyncClick();
    if (b.id === 'wfind') return warFind();
    if (b.id === 'tst') {
      startAlarm({ name: 'Test', dest: 'Mexico' });
      const go = () => notify('TornScope', 'Notification test');
      try { Notification.requestPermission().then(go, go); } catch (e) { go(); }
      return;
    }
  });
  $('#wplane').innerHTML = PLANES.map(([n]) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
  $('#wplane').value = W.plane; $('#wfid').value = W.fid; $('#won').checked = W.on; $('#wall').checked = W.all;
  $('#won').addEventListener('change', (e) => warToggle(e.target.checked));
  $('#wall').addEventListener('change', (e) => { W.all = e.target.checked; warSave(); render(); });
  $('#wplane').addEventListener('change', (e) => { W.plane = e.target.value; warSave(); render(); });
  $('#wfid').addEventListener('keydown', (e) => { if (e.key === 'Enter') warSyncClick(); });
  $('#nid').addEventListener('keydown', (e) => { if (e.key === 'Enter') addTarget(); });
  root.addEventListener('change', (e) => {
    const sel = e.target.closest('select[data-plane]');
    if (!sel) return;
    const t = targets.find(x => x.id === sel.dataset.plane);
    if (!t) return;
    t.plane = PLANES.some(([name]) => name === sel.value) ? sel.value : 'Airstrip';
    saveTargets();
    render();
  });
  $('#key').addEventListener('change', (e) => store.set('key', e.target.value.trim()));
  $('#fast').addEventListener('change', (e) => { store.set('fast', Math.max(3, Math.min(30, +e.target.value || 5))); e.target.value = cfg().fast; render(); });
  $('#snd').addEventListener('change', (e) => store.set('sound', e.target.checked));
  $('#ntf').addEventListener('change', (e) => store.set('notif', e.target.checked));

  async function addTarget() {
    const id = $('#nid').value.trim();
    if (!/^\d+$/.test(id)) return msg('Invalid ID (digits only)');
    if (unverified()) return msg('Waiting for the sync server — try again in a moment');
    if (account && id === account.id) return msg("You can't track your own account");
    if (targets.some(t => t.id === id)) return msg('Target already added');
    if (targets.length >= maxTargets()) return msg(`Maximum ${maxTargets()} targets with a check every ${cfg().fast} s`);
    let name = '';
    if (account) { // sync mode: the server must accept it first, so lists can never drift apart
      msg('Adding…');
      const r = await exclusive(() => overlayRequest('POST', '/overlay/targets', { targetTornId: id }));
      if (r.status === 401) { onAuthFailed(); return msg('Token rejected — target not added'); }
      if (!isOk(r)) return msg(isTransient(r) ? 'Cannot reach the sync server — target not added' : safeText((r.data && r.data.message) || 'Server refused this player'));
      name = (r.data.target && r.data.target.name) || '';
      if (targets.some(t => t.id === id)) return render();
    }
    const t = { id, name, lastUntil: 0, lastFlightKey: '', plane: 'Airstrip' }; targets.push(t); saveTargets();
    const L = ensureLive(t); L.seen = false; L.nextAt = 0;
    $('#nid').value = ''; render();
  }

  /* ----- HUD layout (desktop + phone / Torn PDA) ----- */
  const hudEl = $('#hud'), hdEl = $('#hd');
  const mob = (window.matchMedia && matchMedia('(pointer:coarse)').matches) || window.innerWidth < 600;
  if (mob) hudEl.classList.add('mob');
  if (store.get('min', false) === true) hudEl.classList.add('min');

  function applyDock(ignorePos) {
    let pos = ignorePos === true ? null : store.get('pos', null);
    if (!pos || typeof pos !== 'object' || !Number.isFinite(pos.x) || !Number.isFinite(pos.y)) pos = null;
    const dock = store.get('dock', mob ? 'top' : 'bottom') === 'top' ? 'top' : 'bottom';
    ['left', 'right', 'top', 'bottom'].forEach(k => { hudEl.style[k] = 'auto'; });
    if (pos) { // dragged position, clamped to the screen
      const w = Math.min(hudEl.getBoundingClientRect().width, window.innerWidth);
      hudEl.style.left = Math.min(Math.max(0, pos.x), Math.max(0, window.innerWidth - w)) + 'px';
      hudEl.style.top = Math.min(Math.max(0, pos.y), Math.max(0, window.innerHeight - 48)) + 'px';
    } else {
      hudEl.style.left = mob ? '8px' : '10px';
      if (dock === 'top') hudEl.style.top = 'calc(8px + env(safe-area-inset-top, 0px))';
      else hudEl.style.bottom = mob ? 'calc(76px + env(safe-area-inset-bottom, 0px))' : '10px'; // 76px clears Torn PDA's bottom toolbar
    }
    // safety net: if the HUD is not visibly on screen, forget the saved position and use the default dock
    const r = hudEl.getBoundingClientRect();
    if (window.innerHeight > 0 && r.width > 0 && (r.bottom < 24 || r.top > window.innerHeight - 24 || r.right < 24 || r.left > window.innerWidth - 24)) {
      if (pos) { store.set('pos', null); applyDock(true); }
      else if (dock === 'bottom') { store.set('dock', 'top'); applyDock(true); }
    }
  }
  function flipDock() {
    store.set('pos', null);
    store.set('dock', store.get('dock', mob ? 'top' : 'bottom') === 'top' ? 'bottom' : 'top');
    applyDock();
  }

  (function drag() {
    let sx, sy, ox, oy, on = false, moved = false;
    hdEl.addEventListener('pointerdown', (e) => {
      if (e.target.closest('button,a')) return;
      const r = hudEl.getBoundingClientRect();
      sx = e.clientX; sy = e.clientY; ox = r.left; oy = r.top; on = true; moved = false;
      try { hdEl.setPointerCapture(e.pointerId); } catch (err) {}
    });
    hdEl.addEventListener('pointermove', (e) => {
      if (!on) return;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      if (!moved && Math.abs(dx) + Math.abs(dy) < 6) return;
      moved = true;
      hudEl.style.right = 'auto'; hudEl.style.bottom = 'auto';
      hudEl.style.left = Math.min(window.innerWidth - 60, Math.max(0, ox + dx)) + 'px';
      hudEl.style.top = Math.min(window.innerHeight - 48, Math.max(0, oy + dy)) + 'px';
    });
    hdEl.addEventListener('pointerup', () => {
      if (!on) return; on = false;
      if (moved) { const r = hudEl.getBoundingClientRect(); store.set('pos', { x: Math.round(r.left), y: Math.round(r.top) }); }
      else { hudEl.classList.toggle('min'); store.set('min', hudEl.classList.contains('min')); } // tap the title bar = collapse / expand
    });
    hdEl.addEventListener('pointercancel', () => { on = false; });
  })();
  window.addEventListener('resize', () => applyDock());
  window.addEventListener('orientationchange', () => setTimeout(applyDock, 300));
  window.addEventListener('load', () => applyDock());
  applyDock();
  setTimeout(applyDock, 600); setTimeout(applyDock, 2000); // the phone viewport can settle after load

  /* ----- Initialization ----- */
  $('#key').value = isPDA() ? '' : store.get('key', '');
  if (isPDA()) { $('#key').placeholder = 'API key provided by Torn PDA'; $('#key').disabled = true; }
  $('#fast').value = cfg().fast;
  $('#snd').checked = cfg().sound;
  $('#ntf').checked = cfg().notif;
  $('#sh').textContent = `Safety cap: ${API_CAP} requests/min (Torn limit: 100 per key). Other scripts using the same key count too.`;
  render();
  setInterval(render, 1000); // live countdown and gauge

  // Tracking never starts before the account list is confirmed (token mode) — see maybeAutoStart().
  if (getOverlayToken()) {
    setSync('connecting', 'Connecting…');
    syncNow('startup').then(() => maybeAutoStart());
  } else {
    setSync('off');
    maybeAutoStart();
  }
  setInterval(() => {
    if (!getOverlayToken() || sync.busy || sync.state === 'auth') return;
    if (Date.now() - sync.last >= SYNC_EVERY) syncNow('timer');
  }, 5000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && getOverlayToken() && !sync.busy && sync.state !== 'auth' && Date.now() - sync.last > 15000) syncNow('timer');
  });
})();
console.log(
  '[TornScope 3.4] PDA_httpGet:',
  typeof window.PDA_httpGet,
  '| PDA_httpPost:',
  typeof window.PDA_httpPost
);
