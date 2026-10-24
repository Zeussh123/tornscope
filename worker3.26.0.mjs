const ADMIN_TORN_ID = "4268037";
const ADMIN_USERNAME = "Zeussh";
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_ITERATIONS = 100000;

const encoder = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
    }
  });

function randomToken(bytes = 32) {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(bytes)),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256(value) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(
    new Uint8Array(hash),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

async function hashPassword(password, salt = randomToken()) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: encoder.encode(salt),
      iterations: PBKDF2_ITERATIONS
    },
    key,
    256
  );

  const hash = Array.from(
    new Uint8Array(bits),
    b => b.toString(16).padStart(2, "0")
  ).join("");

  return `${salt}:${hash}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;

  const parts = stored.split(":");
  if (parts.length !== 2) return false;

  const candidate = await hashPassword(password, parts[0]);
  return timingSafeEqual(candidate, stored);
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const entry = cookie.split(";")
    .map(v => v.trim())
    .find(v => v.startsWith(`${name}=`));

  return entry ? entry.slice(name.length + 1) : null;
}

function sessionCookie(token, maxAge = SESSION_SECONDS) {
  return `ttw_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function requireAdmin(account) {
  return Boolean(account && account.role === "admin");
}

async function hashOverlayToken(token) {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function createOverlayToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function getOverlayAccount(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([a-f0-9]{64})$/i);

  if (!match) return null;

  const tokenHash = await hashOverlayToken(match[1]);

  const row = await env.DB.prepare(`
    SELECT users.id AS user_id,
           users.torn_user_id AS torn_user_id,
           users.display_name AS username
    FROM overlay_tokens
    JOIN users ON users.id = overlay_tokens.user_id
    WHERE overlay_tokens.token_hash = ?
      AND overlay_tokens.revoked_at IS NULL
    LIMIT 1
  `).bind(tokenHash).first();

  if (!row) return null;

  await env.DB.prepare(`
    UPDATE overlay_tokens
    SET last_used_at = CURRENT_TIMESTAMP
    WHERE token_hash = ?
      AND revoked_at IS NULL
  `).bind(tokenHash).run();

  return row;
}

async function getAccount(request, env) {
  const token = cookieValue(request, "ttw_session");

  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return null;
  }

  const tokenHash = await sha256(token);

  return await env.DB.prepare(`
    SELECT a.id, a.username, a.torn_user_id, a.role
    FROM sessions s
    JOIN accounts a ON a.id = s.account_id
    WHERE s.token_hash = ?
      AND s.expires_at > unixepoch()
      AND a.active = 1
  `).bind(tokenHash).first();
}

async function createInvitation(env, accountId, validityDays = 7) {
  const code = randomToken(32);
  const codeHash = await sha256(code);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    validityDays * 24 * 60 * 60;

  await env.DB.prepare(`
    INSERT INTO invitations (code_hash, created_by, expires_at)
    VALUES (?, ?, ?)
  `).bind(codeHash, accountId, expiresAt).run();

  return { code, expiresAt };
}

// ---- Owner-key request counter. Every call to Torn made with the owner's key is counted per minute (in memory),
// then flushed to D1 in one write. Only a number is kept, never the key.
const API_LIMIT_PER_MIN = 100;
let OWNER_KEY_PARTS = [];
const USAGE_BUF = new Map();

function rememberOwnerKeys(env) {
  OWNER_KEY_PARTS = [env.TORN_API_KEY, env.COLLECTOR_API_KEY]
    .map(k => String(k || "")).filter(Boolean).map(k => "key=" + encodeURIComponent(k));
}

async function tornFetch(url, opts) {
  try {
    const u = String(url);
    if (OWNER_KEY_PARTS.some(p => u.includes(p))) {
      const m = Math.floor(Date.now() / 60000);
      USAGE_BUF.set(m, (USAGE_BUF.get(m) || 0) + 1);
    }
  } catch (_) { /* counting must never break a call */ }
  return fetch(url, opts);
}

async function flushUsage(env) {
  if (!USAGE_BUF.size) return;
  const rows = [...USAGE_BUF.entries()];
  USAGE_BUF.clear();
  try {
    await env.DB.batch(rows.map(([m, n]) => env.DB.prepare(
      "INSERT INTO api_usage (minute, n) VALUES (?, ?) ON CONFLICT(minute) DO UPDATE SET n = n + excluded.n").bind(m, n)));
    if (Math.floor(Date.now() / 60000) % 60 === 7) {
      await env.DB.prepare("DELETE FROM api_usage WHERE minute < ?").bind(Math.floor(Date.now() / 60000) - 2880).run();
    }
  } catch (error) {
    console.error("api_usage flush failed:", error?.name || "error");
  }
}

async function apiUsageReport(env) {
  await flushUsage(env);
  const nowM = Math.floor(Date.now() / 60000);
  const rows = (await env.DB.prepare("SELECT minute, n FROM api_usage WHERE minute > ? ORDER BY minute").bind(nowM - 180).all()).results || [];
  const by = new Map(rows.map(r => [Number(r.minute), Number(r.n)]));
  const minutes = [];
  for (let m = nowM - 59; m <= nowM; m++) minutes.push({ m: m * 60, n: by.get(m) || 0 });
  const vals = minutes.map(x => x.n);
  const last5 = vals.slice(-5);
  const day = (await env.DB.prepare("SELECT COALESCE(SUM(n),0) AS t FROM api_usage WHERE minute > ?").bind(nowM - 1440).first()) || {};
  return {
    limit: API_LIMIT_PER_MIN, cap: COLLECT_HARD_MAX_POLLS, minutes,
    peak: Math.max(0, ...vals), avg5: Math.round(last5.reduce((a, b) => a + b, 0) / 5 * 10) / 10,
    avg60: Math.round(vals.reduce((a, b) => a + b, 0) / 60 * 10) / 10,
    total24h: Number(day.t || 0)
  };
}

async function verifyTornIdentity(env, tornUserId, expectedName = null) {
  const tornUrl = new URL(
    `https://api.torn.com/user/${encodeURIComponent(tornUserId)}`
  );

  tornUrl.searchParams.set("selections", "basic");
  tornUrl.searchParams.set("key", env.TORN_API_KEY);

  const response = await tornFetch(tornUrl.toString());

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("Invalid response from the Torn API");
  }

  if (
    !response.ok ||
    data.error ||
    String(data.player_id) !== String(tornUserId) ||
    typeof data.name !== "string" ||
    !data.name.trim()
  ) {
    console.error("Vérification Torn échouée", {
      httpStatus: response.status,
      apiError: data?.error || null
    });

    return null;
  }

  if (
    expectedName !== null &&
    data.name.toLowerCase() !== expectedName.toLowerCase()
  ) {
    return null;
  }

  return {
    tornUserId: String(data.player_id),
    name: data.name
  };
}

async function ensureAppUser(env, tornUserId, displayName) {
  await env.DB.prepare(`
    INSERT INTO users (torn_user_id, display_name)
    SELECT ?, ?
    WHERE NOT EXISTS (
      SELECT 1 FROM users WHERE torn_user_id = ?
    )
  `).bind(
    String(tornUserId),
    displayName,
    String(tornUserId)
  ).run();

  return await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE torn_user_id = ?
  `).bind(String(tornUserId)).first();
}


const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;
const RESET_CODE_SECONDS = 60 * 60;

// Comparaison à temps constant (évite de révéler un hash caractère par caractère).
function timingSafeEqual(a, b) {
  const x = encoder.encode(String(a));
  const y = encoder.encode(String(b));
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);

  for (let i = 0; i < length; i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }

  return diff === 0;
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= MIN_PASSWORD_LENGTH &&
    password.length <= MAX_PASSWORD_LENGTH
  );
}

// Tables added by the later phases. "IF NOT EXISTS": no existing table is touched.
const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS auth_attempts (bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, window_start INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS password_resets (code_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL, created_by INTEGER, expires_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS travel_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, client_id TEXT NOT NULL, target_torn_id TEXT NOT NULL, target_name TEXT, event_type TEXT NOT NULL, state_from TEXT, state_to TEXT, description TEXT, country TEXT, direction TEXT, observed_at INTEGER NOT NULL, landing_at INTEGER, landing_source TEXT, duration_min INTEGER, quality TEXT NOT NULL DEFAULT 'observed', plane TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_events_client ON travel_events (user_id, client_id)`,
  `CREATE INDEX IF NOT EXISTS idx_events_user_time ON travel_events (user_id, observed_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_events_user_target ON travel_events (user_id, target_torn_id, observed_at DESC)`,
  `CREATE TABLE IF NOT EXISTS user_prefs (account_id INTEGER PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  // ---- autonomous collector (one row per UNIQUE watched player, shared by every user watching him)
  `CREATE TABLE IF NOT EXISTS watch_targets (target_torn_id TEXT PRIMARY KEY, name TEXT, state TEXT, description TEXT, until INTEGER, la_ts INTEGER, la_status TEXT, flight_started_at INTEGER, first_seen_at INTEGER, last_polled_at INTEGER, last_change_at INTEGER, next_poll_at INTEGER NOT NULL DEFAULT 0, polls INTEGER NOT NULL DEFAULT 0, error_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_error_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE INDEX IF NOT EXISTS idx_watch_due ON watch_targets (next_poll_at)`,
  // ---- facts observed by the server (never estimated)
  `CREATE TABLE IF NOT EXISTS target_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE, target_torn_id TEXT NOT NULL, event_type TEXT NOT NULL, state_from TEXT, state_to TEXT, description TEXT, country TEXT, direction TEXT, observed_at INTEGER NOT NULL, observed_after INTEGER, landing_at INTEGER, landing_source TEXT, duration_min INTEGER, quality TEXT NOT NULL DEFAULT 'observed', created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE INDEX IF NOT EXISTS idx_tevents_target_time ON target_events (target_torn_id, observed_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_tevents_time ON target_events (observed_at DESC)`,
  // ---- hours in which an action of the player was seen (UTC hour number), for activity statistics
  `CREATE TABLE IF NOT EXISTS target_activity (target_torn_id TEXT NOT NULL, hour_utc INTEGER NOT NULL, PRIMARY KEY (target_torn_id, hour_utc)) WITHOUT ROWID`,
  // ---- health indicators
  `CREATE TABLE IF NOT EXISTS collector_state (id INTEGER PRIMARY KEY CHECK (id = 1), last_run_at INTEGER, last_run_trigger TEXT, last_success_at INTEGER, last_poll_at INTEGER, runs_total INTEGER NOT NULL DEFAULT 0, polls_total INTEGER NOT NULL DEFAULT 0, errors_total INTEGER NOT NULL DEFAULT 0, events_total INTEGER NOT NULL DEFAULT 0, halted_until INTEGER NOT NULL DEFAULT 0, halted_reason TEXT, last_error TEXT, last_error_at INTEGER)`,
  `INSERT OR IGNORE INTO collector_state (id) VALUES (1)`,
  `CREATE TABLE IF NOT EXISTS collector_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at INTEGER NOT NULL, duration_ms INTEGER, trigger TEXT, due INTEGER, polled INTEGER, ok INTEGER, errors INTEGER, events INTEGER, deferred INTEGER, note TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_runs_time ON collector_runs (started_at DESC)`,
  // ---- per-user Torn API key (AES-GCM encrypted; the plain key is never stored, shown or logged)
  `CREATE TABLE IF NOT EXISTS premium (account_id INTEGER PRIMARY KEY, premium_until INTEGER NOT NULL, updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE TABLE IF NOT EXISTS premium_credits (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, hours INTEGER NOT NULL, source TEXT NOT NULL, ref TEXT NOT NULL UNIQUE, note TEXT, created_by INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE INDEX IF NOT EXISTS idx_credits_account ON premium_credits (account_id, created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS owner_key (id INTEGER PRIMARY KEY CHECK (id = 1), enc TEXT NOT NULL, torn_id TEXT NOT NULL, torn_name TEXT, access_type TEXT, status TEXT NOT NULL DEFAULT 'valid', last_check_at INTEGER, last_error TEXT, updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`,
  `CREATE TABLE IF NOT EXISTS account_affil (account_id INTEGER PRIMARY KEY, same_faction INTEGER NOT NULL DEFAULT 0, same_company INTEGER NOT NULL DEFAULT 0, checked_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS owner_affil (id INTEGER PRIMARY KEY CHECK (id = 1), faction_id INTEGER NOT NULL DEFAULT 0, company_id INTEGER NOT NULL DEFAULT 0, checked_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS war_config (account_id INTEGER PRIMARY KEY, faction_id INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS war_state (faction_id INTEGER PRIMARY KEY, faction_name TEXT, checked_at INTEGER NOT NULL DEFAULT 0, last_ok_at INTEGER NOT NULL DEFAULT 0, last_error TEXT, member_count INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS war_members (faction_id INTEGER NOT NULL, member_id TEXT NOT NULL, name TEXT, level INTEGER NOT NULL DEFAULT 0, state TEXT, description TEXT, until INTEGER NOT NULL DEFAULT 0, last_action INTEGER NOT NULL DEFAULT 0, country TEXT, direction TEXT, plane TEXT, takeoff_at INTEGER NOT NULL DEFAULT 0, duration INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (faction_id, member_id))`,
  `CREATE TABLE IF NOT EXISTS war_flights (faction_id INTEGER NOT NULL, member_id TEXT NOT NULL, member_name TEXT, country TEXT, direction TEXT, plane TEXT, takeoff_at INTEGER NOT NULL DEFAULT 0, landing_at INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (faction_id, member_id, landing_at))`,
  `CREATE TABLE IF NOT EXISTS stock_snapshot (country TEXT PRIMARY KEY, updated_at INTEGER NOT NULL DEFAULT 0, items TEXT NOT NULL DEFAULT '[]')`,
  `CREATE TABLE IF NOT EXISTS stock_events (id INTEGER PRIMARY KEY AUTOINCREMENT, country TEXT NOT NULL, item_id INTEGER NOT NULL, name TEXT, prev_at INTEGER NOT NULL DEFAULT 0, seen_at INTEGER NOT NULL, qty_before INTEGER NOT NULL DEFAULT 0, qty_after INTEGER NOT NULL DEFAULT 0, cost INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_stock_events_ci ON stock_events (country, item_id, seen_at)`,
  `CREATE INDEX IF NOT EXISTS idx_stock_events_seen ON stock_events (seen_at)`,
  `CREATE TABLE IF NOT EXISTS stock_hist (country TEXT NOT NULL, item_id INTEGER NOT NULL, ts INTEGER NOT NULL, qty INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_stock_hist_ci ON stock_hist (country, item_id, ts)`,
  `CREATE INDEX IF NOT EXISTS idx_stock_hist_ts ON stock_hist (ts)`,
  `CREATE TABLE IF NOT EXISTS stock_cycle (id INTEGER PRIMARY KEY AUTOINCREMENT, country TEXT NOT NULL, item_id INTEGER NOT NULL, start_at INTEGER NOT NULL, qty_start INTEGER NOT NULL DEFAULT 0, end_at INTEGER NOT NULL DEFAULT 0, soldout_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_stock_cycle_ci ON stock_cycle (country, item_id, start_at)`,
  `CREATE TABLE IF NOT EXISTS price_hist (item_id INTEGER NOT NULL, ts INTEGER NOT NULL, value INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_price_hist_i ON price_hist (item_id, ts)`,
  `CREATE TABLE IF NOT EXISTS item_types (item_id INTEGER PRIMARY KEY, type TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS item_prices (item_id INTEGER PRIMARY KEY, name TEXT, market_value INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS stock_state (k TEXT PRIMARY KEY, v TEXT)`,
  `CREATE TABLE IF NOT EXISTS api_usage (minute INTEGER PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS beta_access (account_id INTEGER PRIMARY KEY, granted_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS radar_companies (company_id INTEGER PRIMARY KEY, name TEXT, company_type INTEGER NOT NULL DEFAULT 0, rating INTEGER NOT NULL DEFAULT 0, employees INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, added_at INTEGER NOT NULL DEFAULT 0, last_read_at INTEGER NOT NULL DEFAULT 0, next_read_at INTEGER NOT NULL DEFAULT 0, last_error TEXT, fail_count INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_radar_companies_next ON radar_companies (active, next_read_at)`,
  `CREATE TABLE IF NOT EXISTS radar_players (player_id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, name TEXT, position TEXT, state TEXT, description TEXT, last_action INTEGER NOT NULL DEFAULT 0, country TEXT, direction TEXT, plane_type TEXT, takeoff_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_radar_players_company ON radar_players (company_id)`,
  `CREATE TABLE IF NOT EXISTS radar_flights (player_id INTEGER NOT NULL, takeoff_at INTEGER NOT NULL, company_id INTEGER NOT NULL, country TEXT, direction TEXT, plane_type TEXT, plane TEXT, duration INTEGER NOT NULL DEFAULT 0, win_start INTEGER NOT NULL DEFAULT 0, win_end INTEGER NOT NULL DEFAULT 0, landed_seen_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (player_id, takeoff_at))`,
  `CREATE INDEX IF NOT EXISTS idx_radar_flights_created ON radar_flights (created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_radar_flights_takeoff ON radar_flights (takeoff_at)`,
  `CREATE TABLE IF NOT EXISTS premium_pending (ref TEXT PRIMARY KEY, sender_id TEXT NOT NULL, qty INTEGER NOT NULL, entry_ts INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL DEFAULT (unixepoch()), resolved_at INTEGER, resolved_account INTEGER)`,
  `CREATE TABLE IF NOT EXISTS owner_log_state (id INTEGER PRIMARY KEY CHECK (id = 1), since_ts INTEGER NOT NULL, last_run_at INTEGER, last_ok_at INTEGER, last_error TEXT, checks_total INTEGER NOT NULL DEFAULT 0, credited_total INTEGER NOT NULL DEFAULT 0, pending_total INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS user_keys (account_id INTEGER PRIMARY KEY, enc TEXT NOT NULL, torn_id TEXT NOT NULL, torn_name TEXT, access_type TEXT, status TEXT NOT NULL DEFAULT 'valid', last_check_at INTEGER, last_ok_at INTEGER, last_error TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), updated_at INTEGER NOT NULL DEFAULT (unixepoch()))`
];

let schemaReady = false;

async function ensureSchema(env) {
  if (schemaReady) return;

  try {
    // exec() = a single call to D1, whatever the number of statements (each one on ONE line).
    if (typeof env.DB.exec === "function") {
      await env.DB.exec(SCHEMA_STATEMENTS.map(q => q.replace(/\s+/g, " ").trim() + ";").join("\n"));
    } else {
      for (const q of SCHEMA_STATEMENTS) await env.DB.prepare(q).run();
    }

    schemaReady = true;
  } catch (error) {
    console.error("Schema creation error:", error?.stack || String(error));
  }
}

// Protection contre les essais répétés.
// Retourne le nombre de secondes restantes si le compartiment est bloqué, sinon 0.
async function lockedSeconds(env, bucket) {
  try {
    const row = await env.DB.prepare(`
      SELECT locked_until FROM auth_attempts WHERE bucket = ?
    `).bind(bucket).first();

    const now = nowSeconds();
    return row && row.locked_until > now ? row.locked_until - now : 0;
  } catch (error) {
    console.error("Erreur lecture limite:", error?.stack || String(error));
    return 0;
  }
}

async function registerFailure(env, bucket, maxFailures, windowSeconds, lockSeconds) {
  try {
    const now = nowSeconds();

    const row = await env.DB.prepare(`
      SELECT failures, window_start FROM auth_attempts WHERE bucket = ?
    `).bind(bucket).first();

    if (!row || row.window_start + windowSeconds <= now) {
      await env.DB.prepare(`
        INSERT INTO auth_attempts (bucket, failures, window_start, locked_until)
        VALUES (?, 1, ?, 0)
        ON CONFLICT(bucket) DO UPDATE SET
          failures = 1,
          window_start = excluded.window_start,
          locked_until = 0
      `).bind(bucket, now).run();
    } else if (row.failures + 1 >= maxFailures) {
      await env.DB.prepare(`
        UPDATE auth_attempts
        SET failures = 0, window_start = ?, locked_until = ?
        WHERE bucket = ?
      `).bind(now, now + lockSeconds, bucket).run();
    } else {
      await env.DB.prepare(`
        UPDATE auth_attempts SET failures = failures + 1 WHERE bucket = ?
      `).bind(bucket).run();
    }

    // Nettoyage occasionnel des anciennes lignes.
    if (Math.random() < 0.02) {
      await env.DB.prepare(`
        DELETE FROM auth_attempts
        WHERE window_start < ? AND locked_until < ?
      `).bind(now - 24 * 60 * 60, now).run();
    }
  } catch (error) {
    console.error("Erreur enregistrement échec:", error?.stack || String(error));
  }
}

async function clearFailures(env, bucket) {
  try {
    await env.DB.prepare(`
      DELETE FROM auth_attempts WHERE bucket = ?
    `).bind(bucket).run();
  } catch (error) {
    console.error("Erreur nettoyage limite:", error?.stack || String(error));
  }
}

function tooManyAttempts(seconds) {
  const minutes = Math.max(1, Math.ceil(seconds / 60));

  return json({
    ok: false,
    message: "Too many attempts. Try again in " + minutes + " minute(s)."
  }, 429, {
    "Retry-After": String(seconds)
  });
}

// Pages publiques de récupération (même style que la page de connexion).
const LOGO_SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" fill=\"none\"><g stroke=\"#16D9F2\" stroke-linecap=\"round\" fill=\"none\"><circle cx=\"32\" cy=\"32\" r=\"29\" stroke-width=\"3\"/><circle cx=\"32\" cy=\"32\" r=\"19\" stroke-width=\"2\" stroke-opacity=\".75\"/><circle cx=\"32\" cy=\"32\" r=\"9\" stroke-width=\"2\" stroke-opacity=\".75\"/><path d=\"M32 4v13M32 47v13M4 32h13M47 32h13\" stroke-width=\"1.5\" stroke-opacity=\".5\"/></g><path d=\"M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z\" fill=\"#16D9F2\" fill-opacity=\"0.07\"/><path d=\"M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z\" fill=\"#16D9F2\" fill-opacity=\"0.12\"/><path d=\"M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z\" fill=\"#16D9F2\" fill-opacity=\"0.19\"/><path d=\"M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z\" fill=\"#16D9F2\" fill-opacity=\"0.3\"/><path d=\"M32 32L61.0 31.0\" stroke=\"#16D9F2\" stroke-width=\"2.4\" stroke-linecap=\"round\"/><circle cx=\"47\" cy=\"19\" r=\"3.6\" fill=\"#fff\" fill-opacity=\".2\"/><circle cx=\"47\" cy=\"19\" r=\"2.3\" fill=\"#fff\"/><circle cx=\"41\" cy=\"11.5\" r=\"1.5\" fill=\"#fff\" fill-opacity=\".85\"/><circle cx=\"32\" cy=\"32\" r=\"3\" fill=\"#16D9F2\"/></svg>";
const FAVICON = "data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 64 64%22 fill=%22none%22%3E%3Cg stroke=%22%2316D9F2%22 stroke-linecap=%22round%22 fill=%22none%22%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%2229%22 stroke-width=%223%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%2219%22 stroke-width=%222%22 stroke-opacity=%22.75%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%229%22 stroke-width=%222%22 stroke-opacity=%22.75%22/%3E%3Cpath d=%22M32 4v13M32 47v13M4 32h13M47 32h13%22 stroke-width=%221.5%22 stroke-opacity=%22.5%22/%3E%3C/g%3E%3Cpath d=%22M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.07%22/%3E%3Cpath d=%22M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.12%22/%3E%3Cpath d=%22M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.19%22/%3E%3Cpath d=%22M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.3%22/%3E%3Cpath d=%22M32 32L61.0 31.0%22 stroke=%22%2316D9F2%22 stroke-width=%222.4%22 stroke-linecap=%22round%22/%3E%3Ccircle cx=%2247%22 cy=%2219%22 r=%223.6%22 fill=%22%23fff%22 fill-opacity=%22.2%22/%3E%3Ccircle cx=%2247%22 cy=%2219%22 r=%222.3%22 fill=%22%23fff%22/%3E%3Ccircle cx=%2241%22 cy=%2211.5%22 r=%221.5%22 fill=%22%23fff%22 fill-opacity=%22.85%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%223%22 fill=%22%2316D9F2%22/%3E%3C/svg%3E";

const AUTH_PAGE_CSS = `
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; padding: 24px;
      display: grid; place-items: center;
      background: #0b1020; color: #f1f5f9;
      font-family: Inter, system-ui, Arial, sans-serif;
    }
    .card {
      width: 100%; max-width: 440px; padding: 30px;
      background: #111a2e; border: 1px solid #26334d;
      border-radius: 20px;
    }
    .logo { width: 52px; height: 52px; }
    h1 { font-size: 24px; margin: 12px 0 8px; }
    p { color: #94a3b8; line-height: 1.6; }
    label { display: block; margin: 16px 0 7px; font-size: 14px; }
    input {
      width: 100%; padding: 12px; border-radius: 9px;
      border: 1px solid #394663; background: #0b1020;
      color: white; font-size: 16px;
    }
    button {
      width: 100%; margin-top: 24px; padding: 13px;
      border: 0; border-radius: 10px; cursor: pointer;
      background: #0e7490; color: white;
      font-weight: 700; font-size: 15px;
    }
    #message { margin-top: 16px; font-size: 14px; overflow-wrap: anywhere; }
    a { color: #67e8f9; }
    .hint { font-size: 12px; margin: 6px 0 0; }
`;

function authPage(title, heading, intro, formHtml, scriptJs) {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b1020">
  <link rel="icon" type="image/svg+xml" href="${FAVICON}">
  <meta name="referrer" content="no-referrer">
  <title>${title} — TornScope</title>
  <style>${AUTH_PAGE_CSS}</style>
</head>
<body>
  <main class="card">
    <div class="logo">${LOGO_SVG}</div>
    <h1>${heading}</h1>
    <p>${intro}</p>
    ${formHtml}
    <p><a href="/app">← Back to login</a></p>
  </main>
  <script>${scriptJs}</script>
</body>
</html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

const RECOVER_FORM = `
    <form id="recoverForm">
      <label for="setupToken">Recovery token (ADMIN_SETUP_TOKEN secret)</label>
      <input id="setupToken" type="password" autocomplete="off" required>
      <label for="username">Account to reset</label>
      <input id="username" value="${ADMIN_USERNAME}" autocomplete="off" required maxlength="32">
      <label for="password">New password (12 characters minimum)</label>
      <input id="password" type="password" autocomplete="new-password" required minlength="12" maxlength="128">
      <label for="password2">Confirm the password</label>
      <input id="password2" type="password" autocomplete="new-password" required>
      <button type="submit">Reset the password</button>
      <div id="message" role="status" aria-live="polite"></div>
    </form>`;

const RECOVER_SCRIPT = `
    const form = document.getElementById("recoverForm");
    const message = document.getElementById("message");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const password = document.getElementById("password").value;

      if (password !== document.getElementById("password2").value) {
        message.textContent = "The two passwords do not match.";
        return;
      }

      message.textContent = "Resetting...";

      try {
        const response = await fetch("/admin/recover", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-Admin-Setup-Token": document.getElementById("setupToken").value
          },
          body: JSON.stringify({
            username: document.getElementById("username").value.trim(),
            password: password
          })
        });

        const data = await response.json();
        message.textContent = data.message || (response.ok ? "Password reset." : "Failed.");

        if (response.ok && data.ok) form.reset();
      } catch (error) {
        message.textContent = "Could not reach the server.";
      }
    });
`;

const SCRIPT_URL = "https://greasyfork.org/fr/scripts/601526-tornscope"; // where members install the userscript

const TERMS_PAGE = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0b1020"><meta name="referrer" content="no-referrer">
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
<title>API key and data use — TornScope</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px; background: #0b1020; color: #f1f5f9; font-family: Inter, system-ui, Arial, sans-serif; }
  main { max-width: 760px; margin: 0 auto; background: #111a2e; border: 1px solid #26334d; border-radius: 20px; padding: 28px; }
  h1 { font-size: 24px; margin: 8px 0; }
  p, td { color: #cbd5e1; line-height: 1.6; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th, td { text-align: left; vertical-align: top; padding: 12px; border-top: 1px solid #26334d; }
  th { width: 150px; color: #67e8f9; font-size: 13px; }
  a { color: #67e8f9; }
  .logo { width: 48px; height: 48px; }
  @media (max-width: 560px) { tr { display: block; padding: 10px 0; border-top: 1px solid #26334d; } th, td { display: block; width: auto; padding: 4px 0; border: 0; } }
</style></head>
<body><main>
  <div class="logo">${LOGO_SVG}</div>
  <h1>API key and data use</h1>
  <p>TornScope is a fan-made tool. It only uses the official Torn API, within its limits, and performs no action in the game for you. Here is exactly what happens with your key and your data.</p>
  <table>
<tr><th>Data stored</th><td>In the script: your API key, targets and alerts stay on your device. On our server, only if you link a TornScope account: your account (username, Torn ID, and a password hash only for password accounts), the list of players you watch, the status changes seen for them (state, destination, take-off and landing times), for War mode only: the ID of the enemy faction you chose; your Premium credits and a yes/no flag “same faction / same company as the owner”.</td></tr>
<tr><th>Data shared</th><td>Nothing is sold, published or given to third parties. Each member sees only their own targets and history.</td></tr>
<tr><th>Purpose of use</th><td>Show alerts and history for the players you choose. Premium: the server does the tracking while your browser is closed. War mode (optional): the public member list of the enemy faction you choose is read from Torn (status, travel, last action) to show who is travelling; for Premium the server keeps this public snapshot and the aircraft deduced, shared by members watching the same faction. Public profiles are also read to give members of the owner's faction or company a longer Premium.</td></tr>
<tr><th>Key storage and sharing</th><td>Login: the key you paste to log in is sent once to Torn to check who you are, then discarded; it is not stored. Script: your key stays in your browser or Torn PDA and is sent only to api.torn.com, never to our server. Optional key saved on the site: stored encrypted (AES-256-GCM), never displayed, logged or sent back to your browser, never shared, deletable any time. It may be used to check players watched by other Premium members, only for their public status.</td></tr>
<tr><th>Key access level</th><td>Public access is enough; nothing higher is requested. (Only the owner's own Full key is used, to read the owner's own log and spot Xanax payments; message text is compared with a keyword and not stored.)</td></tr>

  </table>
  <p>You can delete your key at any time from the site. We never ask for your Torn password.</p>
  <p><a href="/">← Back to home</a></p>
</main></body></html>`;

const REGISTER_FORM = `
    <form id="regForm">
      <label for="code">Invitation code</label>
      <input id="code" autocomplete="off" required maxlength="64" spellcheck="false">
      <label for="username">Your Torn name</label>
      <input id="username" autocomplete="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_\\-]+">
      <p class="hint">It must be exactly your name in Torn (letters, digits, _ and - only). It is checked with Torn.</p>
      <label for="tornId">Your Torn ID</label>
      <input id="tornId" inputmode="numeric" autocomplete="off" required pattern="[0-9]{1,12}">
      <label for="password">Choose a password (12 characters minimum)</label>
      <input id="password" type="password" autocomplete="new-password" required minlength="12" maxlength="128">
      <label for="password2">Confirm the password</label>
      <input id="password2" type="password" autocomplete="new-password" required>
      <button type="submit">Create my account</button>
      <div id="message" role="status" aria-live="polite"></div>
    </form>
    <p class="hint" style="margin-top:16px">Then install the TornScope userscript (Tampermonkey or Torn PDA): <a href="${SCRIPT_URL}" target="_blank" rel="noopener noreferrer">Install the script</a> · <a href="/terms">How your data and API key are used</a></p>`;

const REGISTER_SCRIPT = `
    const form = document.getElementById("regForm");
    const message = document.getElementById("message");

    // The invitation code arrives in the link fragment (#code=...), which is never sent to the server.
    const fromLink = new URLSearchParams(window.location.hash.slice(1)).get("code");
    if (fromLink) {
      document.getElementById("code").value = fromLink;
      window.history.replaceState(null, "", "/join");
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const password = document.getElementById("password").value;

      if (password !== document.getElementById("password2").value) {
        message.textContent = "The two passwords do not match.";
        return;
      }

      message.textContent = "Creating your account...";

      try {
        const response = await fetch("/register", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            invitationCode: document.getElementById("code").value.trim(),
            username: document.getElementById("username").value.trim(),
            tornUserId: document.getElementById("tornId").value.trim(),
            password: password
          })
        });

        const data = await response.json();

        if (response.ok && data.ok) {
          form.reset();
          form.innerHTML = '<p>Account created. You can now <a href="/app">log in</a>.</p>';
        } else {
          message.textContent = data.message || "Registration failed.";
        }
      } catch (error) {
        message.textContent = "Could not reach the server.";
      }
    });
`;

const RESET_FORM = `
    <form id="resetForm">
      <label for="code">Reset code</label>
      <input id="code" autocomplete="off" required maxlength="64">
      <label for="password">New password (12 characters minimum)</label>
      <input id="password" type="password" autocomplete="new-password" required minlength="12" maxlength="128">
      <label for="password2">Confirm the password</label>
      <input id="password2" type="password" autocomplete="new-password" required>
      <button type="submit">Set this password</button>
      <div id="message" role="status" aria-live="polite"></div>
    </form>`;

const RESET_SCRIPT = `
    const form = document.getElementById("resetForm");
    const message = document.getElementById("message");

    // Le code peut arriver dans le fragment de l'adresse (#code=...), qui n'est jamais envoyé au serveur.
    const fromLink = new URLSearchParams(window.location.hash.slice(1)).get("code");
    if (fromLink) document.getElementById("code").value = fromLink;

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const password = document.getElementById("password").value;

      if (password !== document.getElementById("password2").value) {
        message.textContent = "The two passwords do not match.";
        return;
      }

      message.textContent = "Saving...";

      try {
        const response = await fetch("/reset", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code: document.getElementById("code").value.trim(),
            password: password
          })
        });

        const data = await response.json();
        message.textContent = data.message || (response.ok ? "Password changed." : "Failed.");

        if (response.ok && data.ok) {
          form.reset();
          window.history.replaceState(null, "", "/reset");
        }
      } catch (error) {
        message.textContent = "Could not reach the server.";
      }
    });
`;


const DASHBOARD_HTML = "<!DOCTYPE html>\n<html lang=\"en\" data-theme=\"dark\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"referrer\" content=\"no-referrer\">\n<meta name=\"color-scheme\" content=\"dark light\">\n<title>TornScope<\/title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 64 64%22 fill=%22none%22%3E%3Cg stroke=%22%2316D9F2%22 stroke-linecap=%22round%22 fill=%22none%22%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%2229%22 stroke-width=%223%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%2219%22 stroke-width=%222%22 stroke-opacity=%22.75%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%229%22 stroke-width=%222%22 stroke-opacity=%22.75%22/%3E%3Cpath d=%22M32 4v13M32 47v13M4 32h13M47 32h13%22 stroke-width=%221.5%22 stroke-opacity=%22.5%22/%3E%3C/g%3E%3Cpath d=%22M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.07%22/%3E%3Cpath d=%22M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.12%22/%3E%3Cpath d=%22M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.19%22/%3E%3Cpath d=%22M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z%22 fill=%22%2316D9F2%22 fill-opacity=%220.3%22/%3E%3Cpath d=%22M32 32L61.0 31.0%22 stroke=%22%2316D9F2%22 stroke-width=%222.4%22 stroke-linecap=%22round%22/%3E%3Ccircle cx=%2247%22 cy=%2219%22 r=%223.6%22 fill=%22%23fff%22 fill-opacity=%22.2%22/%3E%3Ccircle cx=%2247%22 cy=%2219%22 r=%222.3%22 fill=%22%23fff%22/%3E%3Ccircle cx=%2241%22 cy=%2211.5%22 r=%221.5%22 fill=%22%23fff%22 fill-opacity=%22.85%22/%3E%3Ccircle cx=%2232%22 cy=%2232%22 r=%223%22 fill=%22%2316D9F2%22/%3E%3C/svg%3E\">\n<script>\n  (function () {\n    var t = null;\n    try { t = localStorage.getItem('ttw_theme'); } catch (e) {}\n    if (t !== 'light' && t !== 'dark' && t !== 'system') t = 'dark';\n    var dark = t === 'dark' || (t === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);\n    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');\n  })();\n<\/script>\n<style>\n  :root, [data-theme=\"dark\"] {\n    --bg: #0a0f1d; --bg2: #0f1629; --panel: #131c33; --panel2: #18233f; --line: #263250;\n    --text: #eef2f9; --muted: #93a0ba; --accent: #16d9f2; --accent2: #67e8f9; --accent-ink: #04202a; --blip: #ffffff;\n    --gold: #f5b72e; --gold2: #ffe08a; --gold-ink: #3a2600;\n    --ok: #34d399; --warn: #fbbf24; --bad: #f87171; --info: #60a5fa;\n    --shadow: 0 8px 28px rgba(0,0,0,.35);\n  }\n  [data-theme=\"light\"] {\n    --bg: #f4f6fb; --bg2: #ffffff; --panel: #ffffff; --panel2: #f1f4fa; --line: #dde3ef;\n    --text: #131a2c; --muted: #5d6b86; --accent: #0e7490; --accent2: #0891b2; --accent-ink: #fff; --blip: #0e7490;\n    --gold: #e8a317; --gold2: #b7791f; --gold-ink: #3a2600;\n    --ok: #0f9d6b; --warn: #b7791f; --bad: #d83a3a; --info: #2563eb;\n    --shadow: 0 8px 28px rgba(30,41,80,.10);\n  }\n  * { box-sizing: border-box; }\n  html { scroll-behavior: auto; overflow-anchor: auto; }\n  body { margin: 0; background: var(--bg); color: var(--text);\n    font: 15px/1.5 Inter, system-ui, -apple-system, \"Segoe UI\", Roboto, Arial, sans-serif;\n    transition: background .25s, color .25s; }\n  a { color: var(--accent2); text-decoration: none; }\n  a:hover { text-decoration: underline; }\n  h1 { font-size: 24px; margin: 0; letter-spacing: -.01em; }\n  h2 { font-size: 17px; margin: 0 0 4px; }\n  h3 { font-size: 15px; margin: 0 0 8px; }\n  p { margin: 6px 0; }\n  .muted { color: var(--muted); }\n  .small { font-size: 13px; }\n  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }\n\n  /* radar map */\n  .rmapcard { margin-top:16px; padding:12px; }\n  svg.rmap { width:100%; height:auto; display:block; }\n  svg.rmap .land { stroke: color-mix(in srgb, var(--muted) 38%, transparent); stroke-width: 4.2; stroke-linecap: round; fill: none; }\n  svg.rmap .route { fill:none; stroke: var(--accent); stroke-width:1.2; stroke-dasharray:3 5; opacity:.55; }\n  svg.rmap .hotroute { stroke: var(--gold); opacity:.9; }\n  svg.rmap .dest { fill: var(--panel2); stroke: var(--muted); stroke-width:1.2; }\n  svg.rmap .dest.on { fill: var(--accent); stroke: var(--accent); }\n  svg.rmap .home { fill:none; stroke: var(--gold); stroke-width:2; } svg.rmap .homedot { fill: var(--gold); }\n  svg.rmap .lbl { fill: var(--muted); font-size: 12px; } svg.rmap .lbl.on { fill: var(--text); font-weight:600; } svg.rmap .lbl.hot { fill: var(--gold); }\n  svg.rmap .plane path { fill: var(--accent2); stroke: var(--bg); stroke-width:.6; } svg.rmap .plane.back path { fill: var(--gold); }\n  svg.rmap .pulse { fill:none; stroke: var(--gold); stroke-width:2; transform-box: fill-box; transform-origin:center; animation: rpulse 1.8s ease-out infinite; }\n  @keyframes rpulse { 0% { transform: scale(.5); opacity:.9; } 100% { transform: scale(2.2); opacity:0; } }\n  @media (prefers-reduced-motion: reduce) { svg.rmap .pulse { animation:none; } }\n  .rmap-legend { display:flex; gap:16px; flex-wrap:wrap; padding:6px 4px 0; } .rmap-legend .lg.out { color: var(--accent2); } .rmap-legend .lg.back, .rmap-legend .lg.hot { color: var(--gold); }\n  .rtabs { display:flex; gap:6px; flex-wrap:wrap; margin-top:16px; border-bottom:1px solid var(--line); }\n  .rtab { background:none; border:0; border-bottom:2px solid transparent; color: var(--muted); padding:9px 14px; font-weight:600; border-radius:8px 8px 0 0; cursor:pointer; font-size:14px; }\n  .rtab:hover { color: var(--text); } .rtab.on { color: var(--accent); border-bottom-color: var(--accent); }\n  .rmapwrap { position:relative; } .rmap-tip { position:absolute; z-index:5; pointer-events:none; background: var(--bg2); color: var(--text); border:1px solid var(--line); border-radius:10px; padding:8px 10px; font-size:13px; box-shadow: var(--shadow); max-width:290px; line-height:1.35; }\n  .rmap-tip b { display:block; margin-bottom:2px; }\n  svg.rmap .hit { fill: transparent; cursor:pointer; } svg.rmap g[role=button] { outline:none; cursor:pointer; }\n  svg.rmap .plane:hover path, svg.rmap .plane:focus path { filter: brightness(1.35) drop-shadow(0 0 3px var(--accent)); }\n  svg.rmap .destg:hover .dest, svg.rmap .destg:focus .dest, svg.rmap .destg.sel .dest { stroke: var(--gold); stroke-width:3; }\n  svg.rmap .selring { fill:none; stroke: var(--gold); stroke-width:2; } svg.rmap .ghostdot { fill: var(--muted); opacity:.55; } svg.rmap .gh:hover .ghostdot { opacity:1; }\n  svg.rmap g.plane:focus-visible .hit, svg.rmap .destg:focus-visible .hit { stroke: var(--accent); stroke-width:2; }\n  .lg-ico svg { vertical-align:middle; fill: var(--accent2); } .lg-ico { margin-right:2px; }\n  .rprog { height:8px; border-radius:6px; background: var(--panel2); border:1px solid var(--line); overflow:hidden; margin-top:10px; } .rprog > div { height:100%; background: var(--accent); }\n  tr.clk { cursor:pointer; } tr.clk:hover td { background: var(--panel2); }\n  .rctl { display:flex; gap:22px; flex-wrap:wrap; align-items:center; padding:12px 16px; } .rctl label { display:flex; gap:10px; align-items:center; } .rctl input[type=range] { width:180px; accent-color: var(--accent); }\n  .chips { display:flex; gap:6px; flex-wrap:wrap; } .chip { background: var(--panel2); border:1px solid var(--line); border-radius:999px; padding:2px 10px; font-size:12.5px; } .chip.dim { opacity:.5; }\n  .ok-text { color: var(--ok, #34d399); font-weight:600; }\n  .tlayout { display:grid; grid-template-columns: 262px minmax(0,1fr); gap:14px; align-items:start; margin-top:14px; } .tmain { min-width:0; display:flex; flex-direction:column; gap:12px; }\n  @media (max-width: 960px) { .tlayout { grid-template-columns: 1fr; } }\n  .tside { padding:14px; display:flex; flex-direction:column; gap:10px; position:sticky; top:12px; max-height:calc(100vh - 24px); overflow:auto; } .tside-head { display:flex; justify-content:space-between; align-items:center; } .tside .sec { margin-top:6px; display:flex; flex-direction:column; gap:6px; }\n  .tgrid2 { display:grid; grid-template-columns:1fr 1fr; gap:8px; } .pnum { display:flex; flex-direction:column; gap:3px; } .pnum input, .ttool input[type=search], .tside input[type=text] { width:100%; box-sizing:border-box; background: var(--panel2); color: var(--text); border:1px solid var(--line); border-radius:8px; padding:7px 9px; }\n  .pseg { display:inline-flex; border:1px solid var(--line); border-radius:10px; overflow:hidden; } .pseg button { background: var(--panel2); color: var(--muted); border:0; padding:7px 14px; font-weight:600; cursor:pointer; border-radius:0; } .pseg button.on { background: var(--accent); color: var(--accent-ink); }\n  .tside .pseg { display:grid; grid-template-columns:repeat(4,1fr); } .pgroup { display:flex; flex-wrap:wrap; gap:4px 8px; align-items:center; } .pchips { display:flex; flex-wrap:wrap; gap:6px; width:100%; }\n  .pchip { background: var(--panel2); color: var(--muted); border:1px solid var(--line); border-radius:999px; padding:3px 11px; font-size:13px; cursor:pointer; } .pchip.on { color: var(--text); border-color: var(--accent); background: color-mix(in srgb, var(--accent) 16%, var(--panel2)); }\n  .plink { background:none; border:0; color: var(--accent); cursor:pointer; padding:0 4px; font-size:12.5px; text-decoration:underline; }\n  .ttool { padding:10px 14px; display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; } .ttool input[type=search] { width:190px; }\n  .rhead { display:flex; justify-content:space-between; align-items:center; margin-top:2px; } .rcards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }\n  .rcard { text-align:left; background: var(--panel); color: var(--text); border:1px solid var(--line); border-radius:12px; padding:12px 14px; cursor:pointer; } .rcard:hover, .rcard.best { border-color: var(--accent); } .rbig { font-size:22px; font-weight:700; margin:2px 0; }\n  .bad-text { color: var(--bad); } .tmain .tablewrap td, .tmain .tablewrap th { padding-left:10px; padding-right:10px; } tr.detrow > td { padding:0; background: var(--bg2); } .idet { padding:14px; display:flex; flex-direction:column; gap:12px; }\n  .kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:8px; } .kpi { border:1px solid var(--line); border-radius:10px; padding:9px 12px; background: var(--panel); } .kpi.hl { border-color: var(--ok); } .kpi .k { font-size:11px; letter-spacing:.04em; color: var(--muted); text-transform:uppercase; } .kpi .v { font-size:20px; font-weight:700; margin:2px 0; }\n  .lbox { border:1px solid var(--line); border-radius:10px; padding:10px 14px; display:flex; flex-direction:column; gap:2px; } .lbox.ok { border-color: var(--ok); } .lbox.warn { border-color: var(--warn); } .lbox.bad { border-color: var(--bad); background: color-mix(in srgb, var(--bad) 8%, transparent); } .lbox.bad b { color: var(--bad); }\n  .cwrap { padding:12px 14px; } .ctitle { letter-spacing:.04em; margin-bottom:6px; } .tchartwrap { position:relative; } svg.tchart { width:100%; height:auto; display:block; } svg.tchart text { fill: var(--muted); font-size:11px; }\n  svg.tchart .tgrid { stroke: var(--line); stroke-width:1; } svg.tchart .tline { fill:none; stroke-width:1.6; } svg.tchart .tline.stock { stroke: var(--info); } svg.tchart .tarea.stock { fill: color-mix(in srgb, var(--info) 14%, transparent); } svg.tchart .tline.price { stroke: var(--warn); } svg.tchart .tarea.price { fill: color-mix(in srgb, var(--warn) 12%, transparent); }\n  svg.tchart .tmk { stroke-width:1; stroke-dasharray:3 3; } svg.tchart .mk-restock { stroke: var(--ok); } svg.tchart .mk-sold { stroke: var(--bad); } svg.tchart .mk-land { stroke: var(--warn); stroke-dasharray:none; stroke-width:1.6; } svg.tchart .tmk-t { fill: var(--warn); } svg.tchart .tfc { fill: color-mix(in srgb, #a78bfa 14%, transparent); stroke:#a78bfa; stroke-width:1.4; stroke-dasharray:5 4; }\n  .ttip { position:absolute; background: var(--panel2); border:1px solid var(--line); border-radius:8px; padding:4px 8px; font-size:12px; pointer-events:none; white-space:nowrap; } .legend { display:flex; gap:14px; flex-wrap:wrap; margin-top:4px; } .legend .lg::before { content:''; display:inline-block; width:14px; height:0; border-top:2px dashed; margin-right:6px; vertical-align:middle; } .lg.g::before { border-color: var(--ok); } .lg.r::before { border-color: var(--bad); } .lg.o::before { border-color: var(--warn); border-top-style:solid; } .lg.p::before { border-color:#a78bfa; }\n  /* ---------- layout ---------- */\n  .app { display: grid; grid-template-columns: 248px 1fr; min-height: 100vh; }\n  .side { background: var(--bg2); border-right: 1px solid var(--line); padding: 20px 14px;\n    position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; gap: 6px; }\n  .brand { display: flex; align-items: center; gap: 10px; padding: 4px 10px 18px; font-weight: 700; font-size: 16px; }\n  .brand .logo { width: 36px; height: 36px; display: grid; place-items: center; color: var(--accent); }\n  .brand .logo svg, .ico-svg svg { width: 100%; height: 100%; display: block; }\n  .brand .name { font-size: 18px; letter-spacing: -.01em; }\n  .brand .name b { color: var(--accent); font-weight: 700; }\n  .prem-chip { display: inline-flex; align-items: center; gap: 7px; padding: 4px 12px 4px 8px; border-radius: 999px; font-weight: 600;\n    font-size: 13px; text-decoration: none; border: 1px solid color-mix(in srgb, var(--gold) 60%, transparent); white-space: nowrap; transition: transform .15s, background .15s; }\n  .prem-chip .ico-svg { width: 20px; height: 24px; color: var(--accent); }\n  .prem-chip.on { background: linear-gradient(135deg, color-mix(in srgb, var(--gold) 26%, transparent), color-mix(in srgb, var(--gold) 8%, transparent)); color: var(--gold); }\n  .prem-chip.off { background: var(--gold); color: var(--gold-ink); border-color: transparent; }\n  .prem-chip.off .ico-svg { color: var(--gold-ink); }\n  .prem-chip:hover { transform: translateY(-1px); text-decoration: none; }\n  .prem-chip .sub { font-weight: 500; font-size: 12px; opacity: .85; }\n  .hero { display: grid; grid-template-columns: 96px 1fr; gap: 22px; align-items: center; }\n  .hero .big-logo { width: 96px; height: 120px; color: var(--accent); }\n  .hero .big-logo svg { width: 100%; height: 100%; }\n  .hero.on { border-color: color-mix(in srgb, var(--gold) 55%, var(--line)); background: linear-gradient(135deg, color-mix(in srgb, var(--gold) 10%, var(--panel)), var(--panel)); }\n  .countdown { font-size: 30px; font-weight: 700; letter-spacing: -.02em; color: var(--gold); }\n  .btn-gold { display: inline-flex; align-items: center; justify-content: center; padding: 11px 20px; border-radius: 10px; background: var(--gold);\n    color: var(--gold-ink); font-weight: 700; text-decoration: none; border: 0; cursor: pointer; font-size: 15px; }\n  .btn-gold:hover { filter: brightness(1.06); text-decoration: none; }\n  .steps { counter-reset: s; list-style: none; padding: 0; margin: 14px 0 0; display: grid; gap: 14px; }\n  .steps li { counter-increment: s; position: relative; padding-left: 44px; }\n  .steps li::before { content: counter(s); position: absolute; left: 0; top: 0; width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center;\n    background: color-mix(in srgb, var(--accent) 22%, transparent); color: var(--accent2); font-weight: 700; }\n  .shot { display: block; width: 100%; max-width: 704px; height: auto; border-radius: 10px; border: 1px solid var(--line); margin-top: 10px; }\n  .kw { font-family: ui-monospace, Menlo, Consolas, monospace; background: color-mix(in srgb, var(--accent) 18%, transparent); padding: 1px 8px; border-radius: 6px; font-weight: 700; }\n  .feat { display: grid; gap: 14px; grid-template-columns: repeat(3, minmax(0, 1fr)); }\n  @media (max-width: 560px) { .top { padding: 10px 12px; gap: 8px; } #syncBadge, #crumb { display: none; } .top .grow { min-width: 0; } }\n  @media (max-width: 800px) { .feat { grid-template-columns: 1fr; } .hero { grid-template-columns: 1fr; text-align: center; justify-items: center; } .prem-chip .sub { display: none; } }\n  .nav a { display: flex; align-items: center; gap: 11px; padding: 10px 12px; border-radius: 10px;\n    color: var(--muted); font-weight: 500; text-decoration: none; transition: background .15s, color .15s; }\n  .nav a:hover { background: var(--panel2); color: var(--text); }\n  .nav a.active { background: color-mix(in srgb, var(--accent) 18%, transparent); color: var(--text); }\n  .nav a .ico { width: 20px; text-align: center; }\n  .nav .sep { height: 1px; background: var(--line); margin: 10px 6px; }\n  .side .foot { margin-top: auto; padding: 10px; border-top: 1px solid var(--line); font-size: 13px; }\n  .main { min-width: 0; }\n  .top { display: flex; align-items: center; gap: 12px; padding: 18px 28px; border-bottom: 1px solid var(--line);\n    background: color-mix(in srgb, var(--bg) 85%, transparent); backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 5; }\n  .top .grow { flex: 1; min-width: 0; }\n  .burger { display: none; }\n  .content { padding: 24px 28px 60px; max-width: 1240px; margin: 0 auto; animation: fade .25s ease; }\n  @keyframes fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }\n  @media (prefers-reduced-motion: reduce) { .content { animation: none; } * { transition: none !important; } }\n\n  /* ---------- components ---------- */\n  .grid { display: grid; gap: 16px; }\n  .cols-4 { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }\n  .cols-2 { grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }\n  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; padding: 18px; box-shadow: var(--shadow); }\n  .stat .label { color: var(--muted); font-size: 13px; }\n  .stat .value { font-size: 30px; font-weight: 700; letter-spacing: -.02em; margin-top: 4px; }\n  .stat .hint { color: var(--muted); font-size: 12px; margin-top: 2px; }\n  .head { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }\n  .head p { margin: 4px 0 0; }\n  button, .btn { appearance: none; border: 0; cursor: pointer; border-radius: 10px; padding: 10px 14px; font: inherit; font-weight: 600;\n    background: var(--accent); color: var(--accent-ink); transition: filter .15s, transform .05s; text-decoration: none; display: inline-block; }\n  button:hover { filter: brightness(1.1); }\n  button:active { transform: translateY(1px); }\n  button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible { outline: 2px solid var(--accent2); outline-offset: 2px; }\n  button.ghost { background: var(--panel2); color: var(--text); border: 1px solid var(--line); }\n  button.danger { background: var(--bad); color: #fff; }\n  button.sm { padding: 6px 10px; font-size: 13px; }\n  button[disabled] { opacity: .5; cursor: not-allowed; }\n  input, select { font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px; max-width: 100%; }\n  input[type=checkbox] { width: 18px; height: 18px; padding: 0; accent-color: var(--accent); }\n  label.field { display: grid; gap: 5px; font-size: 13px; color: var(--muted); }\n  .filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 14px; }\n  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }\n  .stack { display: grid; gap: 10px; max-width: 440px; }\n  .badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600;\n    background: var(--panel2); border: 1px solid var(--line); color: var(--muted); white-space: nowrap; }\n  .badge.ok { color: var(--ok); } .badge.warn { color: var(--warn); } .badge.bad { color: var(--bad); } .badge.info { color: var(--info); } .badge.acc { color: var(--accent2); }\n  .tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 14px; background: var(--panel); }\n  table { width: 100%; border-collapse: collapse; min-width: 640px; }\n  th, td { text-align: left; padding: 11px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }\n  th { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); background: var(--panel2); white-space: nowrap; user-select: none; }\n  th.sortable { cursor: pointer; } th.sortable:hover { color: var(--text); }\n  tbody tr:last-child td { border-bottom: 0; }\n  tbody tr.click { cursor: pointer; } tbody tr.click:hover { background: var(--panel2); }\n  .pager { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-top: 12px; flex-wrap: wrap; }\n  .empty { padding: 36px 16px; text-align: center; color: var(--muted); }\n  .empty b { display: block; color: var(--text); margin-bottom: 4px; }\n  .note { border-left: 3px solid var(--warn); background: color-mix(in srgb, var(--warn) 10%, transparent); padding: 10px 14px; border-radius: 0 10px 10px 0; font-size: 13px; color: var(--muted); margin: 12px 0; }\n  .note.info { border-color: var(--info); background: color-mix(in srgb, var(--info) 10%, transparent); }\n  .bars { display: grid; gap: 9px; }\n  .hbar { display: grid; grid-template-columns: 120px 1fr 44px; gap: 10px; align-items: center; font-size: 13px; }\n  .hbar .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n  .hbar .track { background: var(--panel2); border-radius: 999px; height: 10px; overflow: hidden; }\n  .hbar .fill { height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--accent), var(--info)); transition: width .5s ease; }\n  .hbar .n { text-align: right; color: var(--muted); }\n  svg.chart { width: 100%; height: auto; display: block; }\n  svg.chart text { fill: var(--muted); font-size: 13px; }\n  svg.chart .bar { fill: var(--accent); transition: opacity .15s; } svg.chart .bar:hover { opacity: .7; }\n  svg.chart .grid { stroke: var(--line); stroke-width: 1; }\n  .switch { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--line); }\n  .switch:last-child { border-bottom: 0; }\n  .switch > span { flex: 1; }\n  .switch .badge, .switch > a + .badge { flex: 0 0 auto; }\n  .seg { display: inline-flex; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }\n  .seg button { border-radius: 0; background: var(--panel); color: var(--muted); padding: 8px 14px; }\n  .seg button.on { background: var(--accent); color: var(--accent-ink); }\n  .toast { position: fixed; right: 18px; bottom: 18px; z-index: 50; background: var(--panel2); border: 1px solid var(--line); box-shadow: var(--shadow);\n    padding: 12px 16px; border-radius: 12px; max-width: 360px; animation: fade .2s ease; }\n  .skeleton { background: linear-gradient(90deg, var(--panel2), var(--panel), var(--panel2)); background-size: 200% 100%; animation: sk 1.2s infinite; border-radius: 10px; height: 18px; }\n  @keyframes sk { to { background-position: -200% 0; } }\n  .crumbs { font-size: 13px; margin-bottom: 8px; }\n  .scrim { display: none; }\n\n  @media (max-width: 860px) {\n    .app { grid-template-columns: 1fr; }\n    .side { position: fixed; z-index: 30; left: 0; top: 0; width: 270px; transform: translateX(-102%); transition: transform .2s; box-shadow: var(--shadow); }\n    body.menu .side { transform: none; }\n    body.menu .scrim { display: block; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 20; }\n    .burger { display: inline-block; padding: 8px 12px; }\n    .top { padding: 12px 16px; } .content { padding: 18px 16px 60px; }\n    .hbar { grid-template-columns: 90px 1fr 36px; }\n    .stat .value { font-size: 26px; }\n  }\n  .tt { width: 100%; border-collapse: collapse; margin: 10px 0; }\n  .tt th, .tt td { text-align: left; vertical-align: top; padding: 8px 6px; border-top: 1px solid var(--line, #26334d); font-size: 12.5px; }\n  .tt th { width: 120px; font-weight: 600; }\n  @media (max-width: 560px) { .tt tr { display: block; } .tt th, .tt td { display: block; width: auto; border: 0; padding: 2px 0; } }\n<\/style>\n<\/head>\n<body>\n<div class=\"app\">\n  <aside class=\"side\" id=\"side\" aria-label=\"Main navigation\">\n    <div class=\"brand\"><div class=\"logo\" id=\"brandLogo\" aria-hidden=\"true\"><\/div><div class=\"name\">Torn<b>Scope<\/b><\/div><\/div>\n    <nav class=\"nav\" id=\"nav\"><\/nav>\n    <div class=\"foot\">\n      <div id=\"who\" class=\"muted\">…<\/div>\n      <div class=\"muted small\" style=\"margin-top:4px\">v3.26.0<\/div>\n      <div class=\"row\" style=\"margin-top:8px\"><button class=\"ghost sm\" id=\"logout\" type=\"button\">Log out<\/button><\/div>\n    <\/div>\n  <\/aside>\n  <div class=\"scrim\" id=\"scrim\"><\/div>\n  <div class=\"main\">\n    <header class=\"top\">\n      <button class=\"ghost burger\" id=\"burger\" type=\"button\" aria-label=\"Menu\">☰<\/button>\n      <div class=\"grow\"><strong id=\"crumb\">Overview<\/strong><\/div>\n      <a class=\"prem-chip off\" id=\"premChip\" href=\"#/premium\" hidden><\/a>\n      <span class=\"badge\" id=\"syncBadge\" title=\"Last refresh\">…<\/span>\n      <button class=\"ghost sm\" id=\"refresh\" type=\"button\">Refresh<\/button>\n      <button class=\"ghost sm\" id=\"themeBtn\" type=\"button\" aria-label=\"Change theme\">Theme<\/button>\n    <\/header>\n    <main class=\"content\" id=\"view\" tabindex=\"-1\"><\/main>\n  <\/div>\n<\/div>\n<script>\n(function () {\n  'use strict';\n\n  /* ================= helpers ================= */\n  const $ = (s, r) => (r || document).querySelector(s);\n  function h(tag, attrs) {\n    const el = document.createElement(tag);\n    if (attrs) for (const k in attrs) {\n      const v = attrs[k];\n      if (v === false || v == null) continue;\n      if (k === 'class') el.className = v;\n      else if (k === 'text') el.textContent = v;\n      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);\n      else if (k === 'value') el.value = v;\n      else el.setAttribute(k, v === true ? '' : v);\n    }\n    for (let i = 2; i < arguments.length; i++) add(el, arguments[i]);\n    return el;\n  }\n  function add(el, c) {\n    if (c == null || c === false) return;\n    if (Array.isArray(c)) c.forEach(x => add(el, x));\n    else el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));\n  }\n  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };\n  async function api(method, path, body) {\n    const opt = { method, credentials: 'same-origin', cache: 'no-store', headers: {} };\n    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }\n    let res, data = null;\n    try { res = await fetch(path, opt); } catch (e) { return { ok: false, status: 0, data: { message: 'Serveur injoignable' } }; }\n    try { data = await res.json(); } catch (e) { data = {}; }\n    if (res.status === 401 && path !== '/account/password') { location.replace('/app'); }\n    return { ok: res.ok && data && data.ok !== false, status: res.status, data: data || {} };\n  }\n  let toastTimer;\n  function toast(text) {\n    const old = $('.toast'); if (old) old.remove();\n    const t = h('div', { class: 'toast', role: 'status', text });\n    document.body.appendChild(t);\n    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.remove(), 4500);\n  }\n  const pad = (n) => String(n).padStart(2, '0');\n  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];\n  const dFmt = (s) => { if (!s) return '—'; const d = new Date(s * 1000); return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear() + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); };\n  const dShort = (k) => Number(k.slice(8)) + ' ' + MONTHS[Number(k.slice(5, 7)) - 1];\n  const dayKey = (s) => { const d = new Date(s * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); };\n  const ago = (s) => {\n    if (!s) return '—';\n    const diff = Math.max(0, Date.now() / 1000 - s);\n    if (diff < 90) return 'just now';\n    if (diff < 3600) return Math.round(diff / 60) + ' min ago';\n    if (diff < 86400) return Math.round(diff / 3600) + ' h ago';\n    return Math.round(diff / 86400) + (Math.round(diff / 86400) === 1 ? ' day ago' : ' days ago');\n  };\n\n  const LOGO = \"<svg xmlns=\\\"http://www.w3.org/2000/svg\\\" viewBox=\\\"0 0 64 64\\\" fill=\\\"none\\\"><g stroke=\\\"currentColor\\\" stroke-linecap=\\\"round\\\" fill=\\\"none\\\"><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"29\\\" stroke-width=\\\"3\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"19\\\" stroke-width=\\\"2\\\" stroke-opacity=\\\".75\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"9\\\" stroke-width=\\\"2\\\" stroke-opacity=\\\".75\\\"/><path d=\\\"M32 4v13M32 47v13M4 32h13M47 32h13\\\" stroke-width=\\\"1.5\\\" stroke-opacity=\\\".5\\\"/><\/g><path d=\\\"M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.07\\\"/><path d=\\\"M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.12\\\"/><path d=\\\"M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.19\\\"/><path d=\\\"M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.3\\\"/><path d=\\\"M32 32L61.0 31.0\\\" stroke=\\\"currentColor\\\" stroke-width=\\\"2.4\\\" stroke-linecap=\\\"round\\\"/><circle cx=\\\"47\\\" cy=\\\"19\\\" r=\\\"3.6\\\" fill=\\\"var(--blip,#fff)\\\" fill-opacity=\\\".2\\\"/><circle cx=\\\"47\\\" cy=\\\"19\\\" r=\\\"2.3\\\" fill=\\\"var(--blip,#fff)\\\"/><circle cx=\\\"41\\\" cy=\\\"11.5\\\" r=\\\"1.5\\\" fill=\\\"var(--blip,#fff)\\\" fill-opacity=\\\".85\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"3\\\" fill=\\\"currentColor\\\"/><\/svg>\";\n  const LOGO_CROWN = \"<svg xmlns=\\\"http://www.w3.org/2000/svg\\\" viewBox=\\\"0 0 64 80\\\" fill=\\\"none\\\"><g transform=\\\"translate(0 16)\\\"><g stroke=\\\"currentColor\\\" stroke-linecap=\\\"round\\\" fill=\\\"none\\\"><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"29\\\" stroke-width=\\\"3\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"19\\\" stroke-width=\\\"2\\\" stroke-opacity=\\\".75\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"9\\\" stroke-width=\\\"2\\\" stroke-opacity=\\\".75\\\"/><path d=\\\"M32 4v13M32 47v13M4 32h13M47 32h13\\\" stroke-width=\\\"1.5\\\" stroke-opacity=\\\".5\\\"/><\/g><path d=\\\"M32 32L41.0 4.4A29 29 0 0 1 48.8 8.4Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.07\\\"/><path d=\\\"M32 32L48.8 8.4A29 29 0 0 1 55.2 14.5Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.12\\\"/><path d=\\\"M32 32L55.2 14.5A29 29 0 0 1 59.3 22.3Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.19\\\"/><path d=\\\"M32 32L59.3 22.3A29 29 0 0 1 61.0 31.0Z\\\" fill=\\\"#16D9F2\\\" fill-opacity=\\\"0.3\\\"/><path d=\\\"M32 32L61.0 31.0\\\" stroke=\\\"currentColor\\\" stroke-width=\\\"2.4\\\" stroke-linecap=\\\"round\\\"/><circle cx=\\\"47\\\" cy=\\\"19\\\" r=\\\"3.6\\\" fill=\\\"var(--blip,#fff)\\\" fill-opacity=\\\".2\\\"/><circle cx=\\\"47\\\" cy=\\\"19\\\" r=\\\"2.3\\\" fill=\\\"var(--blip,#fff)\\\"/><circle cx=\\\"41\\\" cy=\\\"11.5\\\" r=\\\"1.5\\\" fill=\\\"var(--blip,#fff)\\\" fill-opacity=\\\".85\\\"/><circle cx=\\\"32\\\" cy=\\\"32\\\" r=\\\"3\\\" fill=\\\"currentColor\\\"/><\/g><g transform=\\\"translate(2 0) scale(1.0)\\\"><path d=\\\"M15 24L11 7l9 7 7-12 7 12 9-7-4 17z\\\" fill=\\\"#F5B72E\\\" stroke=\\\"#C98A0B\\\" stroke-width=\\\"1.2\\\" stroke-linejoin=\\\"round\\\"/><path d=\\\"M15 24L11 7l9 7 7-12 7 12\\\" fill=\\\"none\\\" stroke=\\\"#FFE08A\\\" stroke-width=\\\"1\\\" stroke-linejoin=\\\"round\\\" stroke-opacity=\\\".8\\\" transform=\\\"translate(0 .2)\\\"/><rect x=\\\"15\\\" y=\\\"24\\\" width=\\\"30\\\" height=\\\"5\\\" rx=\\\"1.5\\\" fill=\\\"#F5B72E\\\" stroke=\\\"#C98A0B\\\" stroke-width=\\\"1.2\\\"/><circle cx=\\\"11\\\" cy=\\\"7\\\" r=\\\"2.2\\\" fill=\\\"#FFE08A\\\"/><circle cx=\\\"27\\\" cy=\\\"2\\\" r=\\\"2.4\\\" fill=\\\"#FFE08A\\\"/><circle cx=\\\"49\\\" cy=\\\"7\\\" r=\\\"2.2\\\" fill=\\\"#FFE08A\\\"/><circle cx=\\\"30\\\" cy=\\\"26.5\\\" r=\\\"1.3\\\" fill=\\\"#16D9F2\\\"/><circle cx=\\\"22\\\" cy=\\\"26.5\\\" r=\\\"1\\\" fill=\\\"#fff\\\" fill-opacity=\\\".8\\\"/><circle cx=\\\"38\\\" cy=\\\"26.5\\\" r=\\\"1\\\" fill=\\\"#fff\\\" fill-opacity=\\\".8\\\"/><\/g><\/svg>\";\n  const SHOT_SEND = \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAsAAAACKCAMAAACTrQz+AAAAkFBMVEXv8+Tc3d3Z3cLex5+z2dzEx7yAwOepo4Ordy9cpdkljsYzc5JYUUVEREQjXq5JPj87Ozs1NTcxMTEqKittJC0kJH8kJCR0HS0iImsiIiIfHyIaGh0ZGRkSEhIQEBAPDw8ODg4NDQ0JCYwMDAwLCwsKCgoJCQkICAgHBwcGBgYFBQUEBAQDAwMCAgIBAQEAAABtJhUtAAALQklEQVR42u2dDYOauBaGQSAhqIyAgHbstJ3OR7vt7v3//+6ecxIUR3ScXbWC78MYkQB+PR5PGBO8CoAe4+ElABAYAAgMwB601lMuJxAY9NXgakIXCAx6yVQzkwMCK7I78eNqEeowfm93STBfl12YoAxjs1VdvrfX/XsjFuGorpR/cBeq+Xwmvu/HeM+HxWSPv2uBTUAKRJpEO4nAUrSrU/+/CEybB4mvD21Pnzz3UYnqd3YGekgURQcbcWkwLyMdzFMKnhFHsDL0KeqJjKRDOqopsNHsqF6EMS/w/YgtSTk06sr4pBcpawNtE4HVqDa8FevlB/PEzvOu7R348cLe2f69mciKSYuojnbDD8KXjSTSlmGwCHlTIzfsY+Zng7d8WBGYBD4YgUnLlFSIjSYlKhVwQDPOKRORsmO2TTcC31G14mq6RZrRYqvslsBK3F/IIorAqeyh+Uzc0WIuA7p5YG/GGsm6xxLVKc+hWEzSUuWCt3YJA+1685iRQgwtB44iHUXTQ404Re5Sodgga6DEQ05eI0N1/K1sgkbgMUdACXNGU7iTBES/EZijIeslYZecsnuQeReA6ZqcO7i3JhFJm934LHAsviteRkFZuxSiecxlCH8Hl0DoSkcHj0IknPsmOqrfCEwqkVRhvE/gNODv/C6BOQKLsNUbgbmdNapDFzerg3tzAlMrjkOwEnutwGOfkwf+IARvBEYCMcAEYmKL/QKnUTSnQldW4PXXMQVRzQcBbAJgM4FWClHJwQH7pZ9wotwSmLKEpEkbtlIIzZ6FklGLwAf25gQ2ku1SwjE3jcB2EdVEOykEuB28rVY8F1bgatMgEl3k6JR8YY+2GnHu8IE0u2iTaKsRl6wbcVS3acQt2o04XR3cmxUypSYgPQCd+JsU4o5zEIrD8vGy6rvHjAh8iwL/a5Q+5eM57d4ABH4HF/5OxGn3BiAwABAYAAgMAAQGEBgACAwABAYAAgMIDAAEBgACAwgMAAQGAAID8AGBE/mtuUFvSNBXgW2vdQgM+ilwwD0iuUeQdAKyQzfw7FzGYuCSK5Xvo8sEuEqBuTuwlv5uPDwED90gIy/EY+6+FtsRGaSvHII0uEaBx9yLmIdz4L6SMnQDxVs72ogdv4HUVVyJEAyuUeC7ULPCzUgOTVKsE+7t2wgMecG1Cjw3PFKIG8nBDt0Q8UhliUsepJQRG/CqgWsUWAYecY04O3QDD+Qw56FvOBlGIw5cscBHkKDLO+itwAajRoOeR2AAIDAAEBgACAwgMAAQGICTCJxNAegFWZfAs+LpHwB6wFMx2xU4K/DCgL5QZDsCT7//DUBP+D7dFfg3AL2hQ+BfAPQGCAyGJvBPAHrDPoGV53n1z9Dz4p+PXD6Gkcx7XAJwxQL/eKWJlY0Tr6a/MPjBpZ2PeV7WwITpCqYOgV8Zirr1qwpojkR+ffS0LT0mfgXgSugQ+EWgxCFQgczELyIwl178AsAV0SXwM01e/RwGkkLEYfAiicSmlDUwYbqCqUPgJybhRtwTNeWCJ9eI49zhSRpxTwBcC/sEfstjGODFAr0Q+Pu3jokE7lyOCdMfnToE/gZAb+gQ+Cvz5etXXOP6+q87BF59+YoJUz+m1a7AWf4AQE/Is44uRfkKLwzoA6t8hk6dYGidOgHAuBAAQGAAIDCAwABAYAAgMAAQGEBgACAwABAYAAgMBiRwyqcxTLvOxZmM6kTOYD+Up6yC+cH6FGckHZzAcuL6gRhcRtHhU47ilLp9FriUs3ynvs+zEb+VTuDBBKYkSOijaILQDww9Sz6Jrqab8zKMTUQL+eTm8KK3ApuA3uGST1pPpW5F4IoXDiKDiMuItY1TX9NzSviTGjuBRzW9DojAfRY4dQGYQ7A1dmACl9GcHHYhd8HqktPaCSwlBO6jwKKnZAmJP9LyFpbbAg8khTC2QQqBBybwgvMFap8bzaaGWlKIeHiNuAU/qbWriyaFkEMtELjHAlfcehNPW424tcDDOYxmv0eakMs6SyOOnn3UWJ2iEddHgQGAwABAYAAgMIDAAEBgACAwAO8LnA92KK186xnnl7iT+8/HcQ8DTyXwLKuWw6TKWoMZVlnx/L8z8Fy0R5xbfT6WFRQ8jcB5thwu2SY85sU/Z6LY3Mn96tOxrBCDTyPwtBqwwNVmQO/p07kEbp0553NVHAutC04i8HLItAT++2y0BM6PBwJD4OsTeHY8EBgCf0jg38yv379Pf90S+ANHLyAwBP6YwL/ONbUEnjgOiNusAoEh8IcE/uuvX3+d59Ih8F6HN/UQGAJfr8Ai68xdGmaztsMQGAJ/SOCfZ2NHYNbU+J6ns9DzvFh5cRaOakXzwWStMASGwDu6aq0n0z8p8DraluFoEno1/eU5CZyLwLHx9AyNuHMJnERM3O3GQulmhlcpw1jWp1nFZRlySXVRvUxpOQ+OQugomF/UXwpuetot8A/LYxj/ODEdAs9SP8jMWuBgbgWmpbPZjsCpYiZw8gQROCUB3xFYFCeLS5oxUW30Mg3mVGu4Z/NS6YWKl3ZlW3U5gfWEy4k+JPAjfaWfX+DZrAy9eKznJHBRUO4QW4FL0roxuC0wyZuYAlL+Z4FLF1JFR7rBwTSW6MrBVdQVgZNAxc53G7LJVaNZ8kSMFYH5w3BZgaftq7cCvzKPYe3FryfmrcCz2SzLE7K2qqzAvq/XAudk8KxD4FTllVFqTCYbZRJFN6kYl2bC9TRreNWmclLJklI1swVvbHdhXOUNCszBk10kda3AHFi1YS3veOgItpEFLqNaOW8XLu0wJD1vntgcguM4r3JJgaeNwJP9ApPCZxW4+TdblmfKG81JYC+o1CgcbQQWg7f+E9dE4ISMNOTqJCVxWdqcS0NVVMkm01pqUipTmrFdIpV0zX8Tu3HOujer35rAEjiVJK9W4ITlTG1666IrC6xiUZ0XlKFmaSWFuHMCL6Usee6KIvDL88sLXUhguT7hZVfgLMuLRegFS4rAFQlsPL8RuMizbEdgmwNzDFVOTWtnZcapKdhLZWMqS01qksCyJJXU2ShJP2jziXGfATX8ENwhsNFri10KwZGVFCSP65bAtoEWy/psckqNNS7jdQpB88tE0ohLCmzbb/ty4IsInFnyvCiqkqKuFZgbcxuBKQYz2xGYU2AztlnClsAUbU2eNDZuBDbNAsobSqPGqaQbTmBzkzmwdY8bZjzMUlQnZCR5GHBbbEtgl2yYpqVmI3AiDTpqxLHatKbE6IsKTO5ONNMp8POTTCSwmzvZ1PVrNFL1ExnLAi9JYOM1RyGKYufXaJJCkHpNztAILDdpqZHMQfRuRWBekoxp49LkHKlt8uBKt/ptCSy5A6Wy0oiTKLtpv8WLHYFTWb1ebB9Go1XkMJpb77ICL/kg2qRtcPv3wAILLNdP7vYJrvcIfCeR10bg1HPHgeMi7xaYUtumEecElkYcV0yqdatsLbBrxJl1I45mDS2+7UbcMSz2HSnu5MICuzi8Mbgl8Pez0SVwYTzP05X7T1y9aP4TNy/O/Xvg9EaOKP9rgdUHDE6iPyAwZxJ/XuDOXhjFOoE4k8DcfBtXEHiIv4X4dja6e2S0zV3fQI8MCNwXgdGlCAKfVOCvZ6MzhZALT3nRms8LCAyBr1jg4nggMAT+kMBfzka7W/3xQOATCXwr40KsHsi1c1xWLYHvjx7Y5B4Cn0bgmxmZJ//88PBwjkveGpnn8+pYMDraiQS+mbHRZvnq4Qys8vadYGy0ywuM0SkxOmW/BQYAAgMAgQGAwAACAwCBAYDAAHRTQGDQZ3IIDHocf/PCK7IZAP0kLwpvBcDVcb/mk/1l33L5iX/Wsg69ayAw6IfAbX9bAv8fB/H/5N3i2W4AAAAASUVORK5CYII=\";\n  function svgEl(markup, cls) { const e = document.createElement('span'); e.className = 'ico-svg ' + (cls || ''); e.innerHTML = markup; e.setAttribute('aria-hidden', 'true'); return e; }\n  const dFull = (s) => s ? WEEKDAYS[wd(s)] + ' ' + dFmt(s) : '—';\n  function leftText(until, short) {\n    let m = Math.max(0, Math.floor((until - Date.now() / 1000) / 60));\n    const d = Math.floor(m / 1440), hh = Math.floor((m % 1440) / 60), mm = m % 60;\n    if (short) return d >= 1 ? d + ' d' : (hh >= 1 ? hh + ' h' : mm + ' min');\n    return (d ? d + (d === 1 ? ' day ' : ' days ') : '') + hh + ' h ' + pad(mm) + ' min';\n  }\n  const daysOf = (hours) => { const d = hours / 24; return (Number.isInteger(d) ? d : Math.round(d * 10) / 10) + (d === 1 ? ' day' : ' days'); };\n  function updateChip() {\n    const el = $('#premChip'); if (!el) return; clear(el);\n    const pr = S.me && S.me.premium;\n    if (!pr) { el.hidden = true; return; }\n    el.hidden = false; el.className = 'prem-chip ' + (pr.active ? 'on' : 'off');\n    el.appendChild(svgEl(LOGO_CROWN));\n    el.appendChild(h('span', { text: pr.active ? 'Premium' : 'Go Premium' }));\n    if (pr.active && !pr.admin && pr.until) el.appendChild(h('span', { class: 'sub', text: '· ' + leftText(pr.until, true) }));\n    el.title = pr.active ? (pr.admin ? 'Premium — administrator (always active)' : 'Premium until ' + dFull(pr.until)) : 'Get Premium';\n    el.setAttribute('aria-label', el.title);\n  }\n  const dur = (m) => m == null ? '—' : (m >= 60 ? Math.floor(m / 60) + ' h ' + pad(Math.round(m % 60)) : Math.round(m) + ' min');\n  const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];\n  const wd = (s) => (new Date(s * 1000).getDay() + 6) % 7;\n  const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y); const m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };\n  const avg = (a) => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;\n  const count = (arr, fn) => { const m = {}; arr.forEach(x => { const k = fn(x); if (k != null && k !== '') m[k] = (m[k] || 0) + 1; }); return m; };\n  const top = (m, n) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n || 10);\n\n  const FLAGS = { 'Mexico': '🇲🇽', 'Cayman Islands': '🇰🇾', 'Canada': '🇨🇦', 'Hawaii': '🌺', 'United Kingdom': '🇬🇧', 'Argentina': '🇦🇷', 'Switzerland': '🇨🇭', 'Japan': '🇯🇵', 'China': '🇨🇳', 'United Arab Emirates': '🇦🇪', 'South Africa': '🇿🇦' };\n  const flag = (name) => { name = String(name || ''); const c = Object.keys(FLAGS).find(n => name === n || name.indexOf(n + ' (') === 0); return c ? FLAGS[c] + ' ' : ''; };\n  function stateBadge(s) {\n    const map = { Okay: ['ok', '✔ Okay'], Traveling: ['acc', '✈ Traveling'], Abroad: ['info', '🌍 Abroad'], Hospital: ['bad', '🏥 Hospital'], Jail: ['warn', '⛓ Jail'] };\n    const m = map[s];\n    return h('span', { class: 'badge ' + (m ? m[0] : ''), text: m ? m[1] : (s || 'Unknown') });\n  }\n  const TYPE = { departure: ['acc', 'Departure'], arrival: ['ok', 'Arrival'], state_change: ['info', 'Status change'] };\n  const typeBadge = (t) => { const m = TYPE[t] || ['', t]; return h('span', { class: 'badge ' + m[0], text: m[1] }); };\n  function qualityBadge(e) {\n    if (e.type === 'departure') {\n      if (e.quality === 'in_flight') return h('span', { class: 'badge warn', title: 'The flight was already underway when first seen: the time shown is when it was first observed, not the take-off.', text: 'Already flying' });\n      if (e.quality === 'inferred') return h('span', { class: 'badge info', title: 'The take-off was missed by a few seconds: the time is rebuilt from the landing time given by Torn and the flight duration (precision about one minute).', text: 'Inferred' });\n      return h('span', { class: 'badge ok', title: 'Take-off seen live by your script.', text: 'Observed' });\n    }\n    return h('span', { class: 'badge ok', text: 'Observed' });\n  }\n  function landingBadge(e) {\n    if (e.type !== 'departure' || !e.landingAt) return '—';\n    return h('span', {}, dFmt(e.landingAt) + ' ', h('span', { class: 'badge ' + (e.landingSource === 'api' ? 'ok' : 'warn'), text: e.landingSource === 'api' ? 'Confirmed (API)' : 'Estimated' }));\n  }\n  const countryOf = (e) => e.country || '';\n  const where = (e) => {\n    if (!e.country) return e.to || e.description || '—';\n    return e.direction === 'return' ? '← ' + flag(e.country) + e.country : (e.type === 'arrival' ? '📍 ' + flag(e.country) + e.country : '→ ' + flag(e.country) + e.country);\n  };\n\n  /* ================= state ================= */\n  const S = { me: null, targets: [], events: [], prefs: { theme: 'dark', alerts: { departure: true, arrival: true, return: true, mute: [] } }, loaded: false, lastLoad: 0, eventsTruncated: false };\n  const view = $('#view');\n\n  function applyTheme(mode) {\n    const dark = mode === 'dark' || (mode === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);\n    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');\n    try { localStorage.setItem('ttw_theme', mode); } catch (e) {}\n  }\n  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if ((S.prefs.theme || 'dark') === 'system') applyTheme('system'); });\n  async function setTheme(mode) {\n    S.prefs.theme = mode; applyTheme(mode);\n    const r = await api('PUT', '/api/prefs', { prefs: S.prefs });\n    if (!r.ok) toast('Theme applied here, but not saved on the server.');\n  }\n\n  /* ================= data loading ================= */\n  async function loadAll(silent) {\n    const [me, tg, pr] = await Promise.all([api('GET', '/me'), api('GET', '/targets'), api('GET', '/api/prefs')]);\n    if (me.ok) S.me = me.data.user;\n    if (tg.ok) S.targets = tg.data.targets || [];\n    if (pr.ok && pr.data.prefs) { S.prefs = Object.assign({}, S.prefs, pr.data.prefs); S.prefs.alerts = Object.assign({ departure: true, arrival: true, return: true, mute: [] }, S.prefs.alerts || {}); applyTheme(S.prefs.theme || 'dark'); }\n    const all = []; let total = 0, offset = 0, ok = true;\n    do {\n      const r = await api('GET', '/api/events?limit=1000&offset=' + offset + '&order=desc');\n      if (!r.ok) { ok = false; break; }\n      total = r.data.total || 0; (r.data.events || []).forEach(e => all.push(e)); offset += 1000;\n      if (!(r.data.events || []).length) break;\n    } while (offset < total && offset < 5000);\n    if (ok) { S.events = all; S.eventsTruncated = total > all.length; }\n    else if (!silent) toast('Could not load the history: the data shown may be out of date.');\n    S.loaded = true; S.lastLoad = Date.now();\n    $('#who').textContent = S.me ? S.me.username + (S.me.role === 'admin' ? ' · admin' : '') : '…';\n    renderNav(); updateBadge(); updateChip();\n  }\n  function initBrand() { const b = $('#brandLogo'); if (b && !b.firstChild) b.innerHTML = LOGO; }\n  function updateBadge() { const b = $('#syncBadge'); b.textContent = 'Updated ' + pad(new Date(S.lastLoad).getHours()) + ':' + pad(new Date(S.lastLoad).getMinutes()); }\n\n  /* ================= routing ================= */\n  const PAGES = [\n    ['overview', '▦', 'Overview'], ['targets', '◎', 'Targets'], ['history', '☰', 'History'],\n    ['stats', '▮', 'Statistics'], ['countries', '⚑', 'Countries'], ['alerts', '🔔', 'Alerts'],\n    ['radar', '📡', 'Radar'], ['war', '⚔', 'War'], ['premium', '♛', 'Premium'], ['settings', '⚙', 'Settings'], ['admin', '🛡', 'Admin']\n  ];\n  function route() {\n    const parts = (location.hash.replace(/^#\\/?/, '') || 'overview').split('/');\n    return { page: parts[0], arg: parts[1] ? decodeURIComponent(parts[1]) : null };\n  }\n  function renderNav() {\n    const cur = route().page, nav = clear($('#nav'));\n    PAGES.forEach(([id, ico, label]) => {\n      if (id === 'admin' && !(S.me && S.me.role === 'admin')) return;\n      if (id === 'radar' && !(S.me && S.me.beta)) return;\n      if (id === 'radar' || (id === 'war' && !(S.me && S.me.beta))) nav.appendChild(h('div', { class: 'sep' }));\n      nav.appendChild(h('a', { href: '#/' + id, class: cur === id ? 'active' : '', 'aria-current': cur === id ? 'page' : false }, h('span', { class: 'ico', text: ico }), label));\n    });\n  }\n  function go(keep) {\n    initBrand();\n    document.body.classList.remove('menu');\n    const r = route(), p = PAGES.find(x => x[0] === r.page) || PAGES[0];\n    $('#crumb').textContent = p[2];\n    document.title = p[2] + ' — TornScope';\n    renderNav();\n    // Silent re-render (keep): freeze the page height and scroll position so the\n    // view does not collapse and jump to the top while it is rebuilt.\n    const keepY = keep ? window.scrollY : 0;\n    if (keep) view.style.minHeight = view.offsetHeight + 'px';\n    const restore = () => { if (keep) window.scrollTo({ top: keepY, left: 0, behavior: 'instant' }); };\n    clear(view);\n    if (!S.loaded) { view.appendChild(h('div', { class: 'grid' }, h('div', { class: 'skeleton', style: 'height:40px;width:40%' }), h('div', { class: 'skeleton', style: 'height:120px' }))); return; }\n    const fn = { overview, targets, history, stats, countries, alerts, radar: radarPage, war: warPage, premium: premiumPage, settings, admin }[p[0]] || overview;\n    try { fn(r.arg); } catch (e) { console.error(e); view.appendChild(h('div', { class: 'card' }, 'This page failed to display.')); }\n    if (!keep) window.scrollTo({ top: 0, left: 0, behavior: 'instant' });\n    else { restore(); requestAnimationFrame(() => { restore(); view.style.minHeight = ''; restore(); }); }\n  }\n  window.addEventListener('hashchange', () => go());\n  // Run a redraw without moving the page: height is frozen while the DOM is rebuilt.\n  function keepScroll(box, fn) {\n    const y = window.scrollY;\n    box.style.minHeight = box.offsetHeight + 'px';\n    try { fn(); } finally {\n      window.scrollTo({ top: y, left: 0, behavior: 'instant' });\n      requestAnimationFrame(() => { box.style.minHeight = ''; window.scrollTo({ top: y, left: 0, behavior: 'instant' }); });\n    }\n  }\n\n  /* ================= building blocks ================= */\n  const head = (title, sub, actions) => h('div', { class: 'head' }, h('div', {}, h('h1', { text: title }), sub ? h('p', { class: 'muted', text: sub }) : null), actions ? h('div', { class: 'row' }, actions) : null);\n  const stat = (label, value, hint) => h('div', { class: 'card stat' }, h('div', { class: 'label', text: label }), h('div', { class: 'value', text: value }), hint ? h('div', { class: 'hint', text: hint }) : null);\n  const empty = (t, s) => h('div', { class: 'empty' }, h('b', { text: t }), s || '');\n  function hbars(entries, total) {\n    if (!entries.length) return empty('No data yet');\n    const max = Math.max.apply(null, entries.map(e => e[1]));\n    return h('div', { class: 'bars' }, entries.map(([k, v]) => h('div', { class: 'hbar' },\n      h('div', { class: 'name', title: k, text: flag(k) + k }),\n      h('div', { class: 'track' }, h('div', { class: 'fill', style: 'width:' + Math.max(3, v / max * 100) + '%' })),\n      h('div', { class: 'n', text: String(v) }))));\n  }\n  function barChart(labels, values, opts) {\n    opts = opts || {};\n    const W = 520, H = 190, L = 30, B = 26, T = 10, n = labels.length;\n    const max = Math.max(1, Math.max.apply(null, values));\n    const bw = (W - L) / n;\n    const ns = 'http://www.w3.org/2000/svg';\n    const svg = document.createElementNS(ns, 'svg');\n    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('class', 'chart'); svg.setAttribute('role', 'img');\n    svg.setAttribute('aria-label', opts.label || 'Chart');\n    const mk = (tag, a, t) => { const e = document.createElementNS(ns, tag); for (const k in a) e.setAttribute(k, a[k]); if (t != null) e.textContent = t; svg.appendChild(e); return e; };\n    [0, .5, 1].forEach(f => { const y = T + (H - B - T) * (1 - f); mk('line', { x1: L, x2: W, y1: y, y2: y, class: 'grid' }); mk('text', { x: 0, y: y + 4 }, Math.round(max * f)); });\n    values.forEach((v, i) => {\n      const bh = (H - B - T) * v / max, x = L + i * bw + bw * .15, y = H - B - bh;\n      const r = mk('rect', { x, y, width: Math.max(1, bw * .7), height: Math.max(v ? 1 : 0, bh), rx: 2, class: 'bar' });\n      const t = document.createElementNS(ns, 'title'); t.textContent = labels[i] + ' : ' + v; r.appendChild(t);\n      const every = Math.ceil(n / (opts.maxLabels || 12));\n      if (i % every === 0) mk('text', { x: x + bw * .35, y: H - 7, 'text-anchor': 'middle' }, labels[i]);\n    });\n    return svg;\n  }\n\n  /* generic sortable / paginated table (persistKey: keeps sort, page and open row when the page refreshes) */\n  const TABLE_MEM = {};\n  const typing = () => { const a = document.activeElement; return !!(a && /INPUT|SELECT|TEXTAREA/.test(a.tagName) && view.contains(a)); };\n  function dataTable(cfg) {\n    const st = cfg.persistKey ? (TABLE_MEM[cfg.persistKey] = TABLE_MEM[cfg.persistKey] || {}) : {};\n    if (st.sort === undefined) { st.sort = cfg.defaultSort || null; st.dir = cfg.defaultDir || 'desc'; st.page = 0; st.open = null; }\n    st.size = cfg.pageSize || 25;\n    const wrap = h('div');\n    function draw() {\n      let rows = cfg.rows.slice();\n      const sc = st.sort && cfg.cols.find(x => x.key === st.sort);\n      if (sc) { const c = sc; const f = c.sortVal || (r => r[c.key]);\n        rows.sort((a, b) => { const x = f(a), y = f(b); const r = x == null ? 1 : y == null ? -1 : (typeof x === 'string' ? x.localeCompare(y) : x - y); return st.dir === 'asc' ? r : -r; }); }\n      const pages = Math.max(1, Math.ceil(rows.length / st.size)); if (st.page >= pages) st.page = pages - 1;\n      const slice = rows.slice(st.page * st.size, (st.page + 1) * st.size);\n      clear(wrap);\n      if (!rows.length) { wrap.appendChild(h('div', { class: 'tablewrap' }, cfg.empty || empty('No results'))); return; }\n      const thead = h('tr', {}, cfg.cols.map(c => h('th', { class: c.sort === false ? '' : 'sortable', 'aria-sort': st.sort === c.key ? (st.dir === 'asc' ? 'ascending' : 'descending') : 'none',\n        onclick: c.sort === false ? null : () => { if (st.sort === c.key) st.dir = st.dir === 'asc' ? 'desc' : 'asc'; else { st.sort = c.key; st.dir = 'desc'; } draw(); } },\n        c.label + (st.sort === c.key ? (st.dir === 'asc' ? ' ▲' : ' ▼') : ''))));\n      const tb = h('tbody', {}, slice.map(r => {\n        const key = cfg.rowKey ? cfg.rowKey(r) : null, open = !!cfg.expand && key !== null && st.open === key;\n        const tr = h('tr', { class: cfg.onRow || cfg.expand ? 'click' : '', 'aria-expanded': cfg.expand ? String(open) : null, onclick: cfg.onRow || cfg.expand ? () => { if (cfg.expand) { st.open = open ? null : key; draw(); } if (cfg.onRow) cfg.onRow(r); } : null }, cfg.cols.map(c => h('td', {}, c.render ? c.render(r) : (r[c.key] == null ? '—' : String(r[c.key])))));\n        return open ? [tr, h('tr', { class: 'detrow' }, h('td', { colspan: String(cfg.cols.length) }, cfg.expand(r)))] : tr;\n      }));\n      wrap.appendChild(h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, thead), tb)));\n      wrap.appendChild(h('div', { class: 'pager' },\n        h('span', { class: 'muted small', text: rows.length + ' result' + (rows.length > 1 ? 's' : '') + ' · page ' + (st.page + 1) + '/' + pages }),\n        h('div', { class: 'row' },\n          h('button', { class: 'ghost sm', disabled: st.page === 0, onclick: () => { st.page--; draw(); } }, '← Previous'),\n          h('button', { class: 'ghost sm', disabled: st.page >= pages - 1, onclick: () => { st.page++; draw(); } }, 'Next →'))));\n    }\n    draw();\n    return { el: wrap, setRows: (r) => { cfg.rows = r; st.page = 0; draw(); } };\n  }\n\n  /* ================= PAGE: overview ================= */\n  function overview() {\n    const dep = S.events.filter(e => e.type === 'departure');\n    const now = Date.now() / 1000;\n    const d7 = dep.filter(e => e.observedAt > now - 7 * 86400);\n    const flying = S.targets.filter(t => t.state === 'Traveling');\n    view.appendChild(head('Overview', 'A summary of your targets and their recent flights.', h('a', { class: 'btn', href: '#/targets' }, '+ Add a target')));\n    view.appendChild(h('div', { class: 'grid cols-4' },\n      stat('Targets watched', String(S.targets.length), flying.length + ' traveling now'),\n      stat('Flights (7 days)', String(d7.length), dep.length + ' recorded in total'),\n      stat('Top destination', (top(count(dep, countryOf), 1)[0] || ['—'])[0], 'over the whole history'),\n      stat('Last event', S.events.length ? ago(S.events[0].observedAt) : '—', S.events.length ? (S.events[0].targetName || S.events[0].targetId) : 'Nothing recorded')));\n    if (!S.events.length) view.appendChild(h('div', { class: 'note info' }, 'No flights recorded yet. Flights appear here as soon as your script (version 2.7 or later) observes one. Past flights from the script’s local history are not reconstructed.'));\n    const cur = h('div', { class: 'card' }, h('h2', { text: 'Current status' }),\n      S.targets.length ? h('div', {}, S.targets.map(t => h('div', { class: 'switch' },\n        h('a', { href: '#/targets/' + t.tornId, style: 'flex:1;font-weight:600', text: t.name || t.tornId }), stateBadge(t.state), h('span', { class: 'muted small', style: 'flex:0 0 auto', text: t.description || '' })))) : empty('No targets', 'Add a player on the Targets page.'));\n    const recent = h('div', { class: 'card' }, h('h2', { text: 'Latest events' }),\n      S.events.length ? h('div', {}, S.events.slice(0, 7).map(e => h('div', { class: 'switch' },\n        typeBadge(e.type), h('span', { text: (e.targetName || e.targetId) + ' ' + where(e) }), h('span', { class: 'muted small', style: 'flex:0 0 auto', text: dFmt(e.observedAt) })))) : empty('Nothing to show'));\n    view.appendChild(h('div', { class: 'grid cols-2', style: 'margin-top:16px' }, cur, recent));\n    const days = []; for (let i = 13; i >= 0; i--) days.push(dayKey(now - i * 86400));\n    const byDay = count(dep, e => dayKey(e.observedAt));\n    view.appendChild(h('div', { class: 'card', style: 'margin-top:16px' }, h('h2', { text: 'Flights per day (last 14 days)' }),\n      barChart(days.map(dShort), days.map(d => byDay[d] || 0), { label: 'Flights per day', maxLabels: 7 })));\n  }\n\n  /* ================= PAGE: targets ================= */\n  function targets(arg) {\n    if (arg) return targetDetail(arg);\n    view.appendChild(head('Targets', 'The players you watch. The list is shared with your script in real time.'));\n    const msg = h('p', { class: 'muted small', role: 'status' });\n    const input = h('input', { type: 'text', inputmode: 'numeric', placeholder: 'Player Torn ID', maxlength: 12, 'aria-label': 'Torn ID', required: true });\n    const form = h('form', { class: 'row', onsubmit: async (ev) => {\n      ev.preventDefault(); const v = input.value.trim();\n      if (!/^\\d{1,12}$/.test(v)) { msg.textContent = 'Invalid ID (digits only).'; return; }\n      msg.textContent = 'Adding…';\n      const r = await api('POST', '/targets', { targetTornId: v });\n      msg.textContent = r.data.message || (r.ok ? 'Added.' : 'Failed.');\n      if (r.ok) { input.value = ''; await loadAll(true); targetsTable.setRows(rows()); }\n    } }, input, h('button', { type: 'submit' }, 'Add'));\n    view.appendChild(h('div', { class: 'card' }, h('h2', { text: 'Add a target' }), form, msg));\n    const dep = S.events.filter(e => e.type === 'departure');\n    const rows = () => S.targets.map(t => ({ id: String(t.tornId), name: t.name || String(t.tornId), state: t.state, desc: t.description, seen: t.lastSeenAt, flights: dep.filter(e => String(e.targetId) === String(t.tornId)).length }));\n    const targetsTable = dataTable({ rows: rows(), defaultSort: 'name', defaultDir: 'asc', onRow: (r) => { location.hash = '#/targets/' + r.id; },\n      empty: empty('No targets', 'Add a Torn ID above.'),\n      cols: [\n        { key: 'name', label: 'Player', sortVal: r => r.name.toLowerCase(), render: r => h('div', {}, h('b', { text: r.name }), h('div', { class: 'muted small mono', text: '#' + r.id })) },\n        { key: 'state', label: 'Status', render: r => stateBadge(r.state), sortVal: r => r.state || '' },\n        { key: 'desc', label: 'Details', render: r => h('span', { class: 'muted', text: r.desc || '—' }) },\n        { key: 'seen', label: 'Last checked', sortVal: r => r.seen || 0, render: r => r.seen ? ago(r.seen) : h('span', { class: 'muted', text: 'not yet' }) },\n        { key: 'flights', label: 'Flights', sortVal: r => r.flights },\n        { key: 'act', label: '', sort: false, render: r => h('button', { class: 'danger sm', onclick: async (ev) => {\n            ev.stopPropagation();\n            if (!confirm('Stop watching ' + r.name + '? (History already recorded is kept.)')) return;\n            const x = await api('DELETE', '/targets', { targetTornId: r.id });\n            toast(x.data.message || (x.ok ? 'Removed.' : 'Failed.')); await loadAll(true); targetsTable.setRows(rows());\n          } }, 'Remove') }\n      ] });\n    view.appendChild(h('div', { style: 'margin-top:16px' }, targetsTable.el));\n  }\n  function targetDetail(id) {\n    const t = S.targets.find(x => String(x.tornId) === id);\n    const ev = S.events.filter(e => String(e.targetId) === id);\n    const dep = ev.filter(e => e.type === 'departure');\n    const name = t ? (t.name || id) : (ev[0] ? ev[0].targetName : id);\n    view.appendChild(h('div', { class: 'crumbs' }, h('a', { href: '#/targets', text: '← All targets' })));\n    view.appendChild(head(name, '#' + id + (t ? '' : ' · no longer watched (history kept)'), h('a', { class: 'btn ghost', href: 'https://www.torn.com/profiles.php?XID=' + encodeURIComponent(id), target: '_blank', rel: 'noopener noreferrer' }, 'Torn profile ↗')));\n    const obsDep = dep.filter(e => e.quality === 'observed' || e.quality === 'inferred');\n    view.appendChild(h('div', { class: 'grid cols-4' },\n      stat('Status', t && t.state ? t.state : '—', t ? (t.description || '') : ''),\n      stat('Flights recorded', String(dep.length), obsDep.length + ' take-offs observed'),\n      stat('Top destination', (top(count(dep, countryOf), 1)[0] || ['—'])[0]),\n      stat('Last flight', dep.length ? ago(dep[0].observedAt) : '—', dep.length ? dFmt(dep[0].observedAt) : '')));\n    const wdc = count(obsDep, e => wd(e.observedAt));\n    view.appendChild(h('div', { class: 'grid cols-2', style: 'margin-top:16px' },\n      h('div', { class: 'card' }, h('h2', { text: 'Destinations' }), hbars(top(count(dep, countryOf), 8))),\n      h('div', { class: 'card' }, h('h2', { text: 'Departure day (observed)' }), barChart(WEEKDAYS, WEEKDAYS.map((_, i) => wdc[i] || 0), { label: 'Departures by weekday' }))));\n    view.appendChild(h('h3', { style: 'margin-top:22px', text: 'Latest events' }));\n    view.appendChild(eventsTable(ev, 10).el);\n  }\n\n  /* ================= events table + filters (History) ================= */\n  function eventsTable(rows, size) {\n    return dataTable({ rows, pageSize: size || 25, defaultSort: 'observedAt', empty: empty('No events', 'Events will appear as soon as the script observes some.'),\n      cols: [\n        { key: 'observedAt', label: 'Date', render: e => h('span', { title: e.observedAfter ? 'Seen between ' + dFmt(e.observedAfter) + ' and ' + dFmt(e.observedAt) + ' (the exact moment is somewhere in between)' : 'Moment of observation' }, dFmt(e.observedAt)) },\n        { key: 'targetName', label: 'Target', sortVal: e => (e.targetName || '').toLowerCase(), render: e => h('a', { href: '#/targets/' + e.targetId, text: e.targetName || e.targetId }) },\n        { key: 'type', label: 'Type', render: e => typeBadge(e.type) },\n        { key: 'country', label: 'Destination', sortVal: e => e.country || '', render: e => where(e) },\n        { key: 'quality', label: 'Reliability', render: qualityBadge },\n        { key: 'source', label: 'Source', render: e => h('span', { class: 'badge', title: e.source === 'server' ? 'Observed by the server (checked about once a minute, even when you are offline).' : 'Observed live by your script.', text: e.source === 'server' ? 'Server' : 'Script' }) },\n        { key: 'landingAt', label: 'Landing', render: landingBadge },\n        { key: 'durationMin', label: 'Duration', render: e => dur(e.durationMin) }\n      ] });\n  }\n  function filterBar(state, onChange, opts) {\n    opts = opts || {};\n    const sel = (key, label, options) => h('label', { class: 'field' }, label, h('select', { onchange: (ev) => { state[key] = ev.target.value; onChange(true); } },\n      options.map(([v, l]) => h('option', { value: v, selected: state[key] === v }, l))));\n    const names = {}; S.events.forEach(e => { names[e.targetId] = e.targetName || e.targetId; }); S.targets.forEach(t => { names[t.tornId] = t.name || t.tornId; });\n    const countries = Object.keys(count(S.events, countryOf)).sort();\n    const bar = h('div', { class: 'filters' },\n      opts.search ? h('label', { class: 'field' }, 'Search', h('input', { type: 'search', placeholder: 'Name, country…', value: state.q || '', oninput: (ev) => { state.q = ev.target.value; onChange(false); } })) : null,\n      sel('target', 'Target', [['', 'All']].concat(Object.entries(names).map(([k, v]) => [String(k), v]))),\n      sel('country', 'Country', [['', 'All']].concat(countries.map(c => [c, c]))),\n      opts.noType ? null : sel('type', 'Type', [['', 'All'], ['departure', 'Departures'], ['arrival', 'Arrivals'], ['state_change', 'Status changes']]),\n      opts.noType ? null : sel('quality', 'Reliability', [['', 'All'], ['observed', 'Observed'], ['inferred', 'Inferred'], ['in_flight', 'Already flying']]),\n      sel('range', 'Period', [['', 'All time'], ['1', '24 hours'], ['7', '7 days'], ['30', '30 days'], ['90', '90 days'], ['custom', 'Custom dates…']]),\n      state.range === 'custom' ? h('label', { class: 'field' }, 'From', h('input', { type: 'date', value: state.from || '', onchange: (ev) => { state.from = ev.target.value; onChange(false); } })) : null,\n      state.range === 'custom' ? h('label', { class: 'field' }, 'To', h('input', { type: 'date', value: state.to || '', onchange: (ev) => { state.to = ev.target.value; onChange(false); } })) : null,\n      h('button', { class: 'ghost sm', onclick: () => { Object.keys(state).forEach(k => { state[k] = ''; }); onChange(true); } }, 'Reset'));\n    return bar;\n  }\n  function applyFilters(list, f) {\n    const now = Date.now() / 1000; let from = 0, to = Infinity;\n    if (f.range && f.range !== 'custom') from = now - Number(f.range) * 86400;\n    if (f.range === 'custom') { if (f.from) from = new Date(f.from + 'T00:00:00').getTime() / 1000; if (f.to) to = new Date(f.to + 'T23:59:59').getTime() / 1000; }\n    const q = (f.q || '').trim().toLowerCase();\n    return list.filter(e => (!f.target || String(e.targetId) === f.target) && (!f.country || e.country === f.country) && (!f.type || e.type === f.type)\n      && (!f.quality || e.quality === f.quality) && e.observedAt >= from && e.observedAt <= to\n      && (!q || ((e.targetName || '') + ' ' + (e.country || '') + ' ' + (e.targetId || '')).toLowerCase().indexOf(q) >= 0));\n  }\n  const FILTERS = { history: {}, stats: {}, countries: {} };\n  function history() {\n    const f = FILTERS.history, wrap = h('div'), tableBox = h('div');\n    let tbl;\n    function redraw(full) {\n      if (full) { clear(wrap); wrap.appendChild(filterBar(f, redraw, { search: true })); wrap.appendChild(tableBox); }\n      const rows = applyFilters(S.events, f);\n      clear(tableBox); tbl = eventsTable(rows, 25); tableBox.appendChild(tbl.el);\n      count_.textContent = rows.length + ' event' + (rows.length > 1 ? 's' : '');\n    }\n    const count_ = h('span', { class: 'muted small' });\n    view.appendChild(head('Flight history', 'Everything your script observed, with the reliability of each piece of information.', [count_,\n      h('button', { class: 'ghost', onclick: () => exportCsv(applyFilters(S.events, f)) }, 'Export CSV')]));\n    view.appendChild(h('div', { class: 'note info' }, h('b', { text: 'Observed' }), ' = your script saw the status change live. ', h('b', { text: 'Inferred' }), ' = the take-off was missed by a few seconds and rebuilt from Torn\\u2019s landing time (about one minute precision). ', h('b', { text: 'Already flying' }), ' = the player was already in the air when the script saw them: the time is the first observation. ', h('b', { text: 'Confirmed (API)' }), ' = landing time provided by Torn; ', h('b', { text: 'Estimated' }), ' = computed by the script from the aircraft. ', h('b', { text: 'Server' }), ' events come from the automatic collector (checked about once a minute, hover a date to see the window); ', h('b', { text: 'Script' }), ' events come from your open browser (more precise).'));\n    view.appendChild(wrap); redraw(true);\n  }\n  function exportCsv(rows) {\n    const esc = (v) => { v = v == null ? '' : String(v); if (/^[=+\\-@\\t\\r]/.test(v)) v = \"'\" + v; return '\"' + v.replace(/\"/g, '\"\"') + '\"'; };\n    const head_ = ['date_utc', 'target_id', 'target', 'type', 'country', 'direction', 'reliability', 'landing_utc', 'landing_source', 'duration_min'];\n    const iso = (s) => s ? new Date(s * 1000).toISOString() : '';\n    const lines = [head_.join(',')].concat(rows.map(e => [iso(e.observedAt), e.targetId, e.targetName, e.type, e.country, e.direction, e.quality, iso(e.landingAt), e.landingSource, e.durationMin].map(esc).join(',')));\n    const a = h('a', { href: URL.createObjectURL(new Blob(['﻿' + lines.join('\\n')], { type: 'text/csv;charset=utf-8' })), download: 'travel-watcher-history.csv' });\n    document.body.appendChild(a); a.click(); a.remove();\n  }\n\n  /* ================= PAGE: statistics ================= */\n  function stats() {\n    const f = FILTERS.stats, box = h('div');\n    function draw(full) {\n      if (full) { clear(view); build(); return; }\n      clear(box);\n      const all = applyFilters(S.events, f);\n      const dep = all.filter(e => e.type === 'departure'), obs = dep.filter(e => e.quality === 'observed' || e.quality === 'inferred');\n      const arr = all.filter(e => e.type === 'arrival' && e.durationMin != null);\n      if (!dep.length) { box.appendChild(h('div', { class: 'card' }, empty('Not enough data', 'No flights match these filters.'))); return; }\n      const span = Math.max(1, (Math.max.apply(null, dep.map(e => e.observedAt)) - Math.min.apply(null, dep.map(e => e.observedAt))) / 86400);\n      const times = obs.map(e => e.observedAt).sort((a, b) => a - b); const gaps = []; for (let i = 1; i < times.length; i++) gaps.push((times[i] - times[i - 1]) / 3600);\n      box.appendChild(h('div', { class: 'grid cols-4' },\n        stat('Flights', String(dep.length), obs.length + ' observed live'),\n        stat('Average', (dep.length / Math.max(1, Math.ceil(span))).toFixed(1) + ' / day', 'over ' + Math.ceil(span) + ' day(s)'),\n        stat('Average duration', dur(avg(arr.map(e => e.durationMin))), arr.length ? arr.length + ' flights measured (landing observed)' : 'no landing observed'),\n        stat('Median gap', gaps.length ? dur(median(gaps) * 60) : '—', 'between two observed departures')));\n      const byDay = count(dep, e => dayKey(e.observedAt)), keys = []; const nDays = Math.min(30, Math.max(7, Math.ceil(span)));\n      for (let i = nDays - 1; i >= 0; i--) keys.push(dayKey(Date.now() / 1000 - i * 86400));\n      const wdc = count(obs, e => wd(e.observedAt)), hc = count(obs, e => new Date(e.observedAt * 1000).getHours());\n      const mc = count(dep, e => { const d = new Date(e.observedAt * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1); });\n      const months = Object.keys(mc).sort();\n      const weeks = count(dep, e => { const d = new Date(e.observedAt * 1000); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); return dayKey(d.getTime() / 1000); });\n      const wk = Object.keys(weeks).sort().slice(-12);\n      box.appendChild(h('div', { class: 'grid cols-2', style: 'margin-top:16px' },\n        h('div', { class: 'card' }, h('h2', { text: 'Flights per day' }), barChart(keys.map(dShort), keys.map(d => byDay[d] || 0), { label: 'Flights per day', maxLabels: 8 })),\n        h('div', { class: 'card' }, h('h2', { text: 'Flights per week' }), wk.length ? barChart(wk.map(dShort), wk.map(d => weeks[d]), { label: 'Flights per week', maxLabels: 8 }) : empty('—')),\n        h('div', { class: 'card' }, h('h2', { text: 'Departure day' }), h('p', { class: 'muted small', text: 'Observed take-offs only (your browser\\u2019s local time).' }), barChart(WEEKDAYS, WEEKDAYS.map((_, i) => wdc[i] || 0), { label: 'Departures per day' })),\n        h('div', { class: 'card' }, h('h2', { text: 'Departure hour' }), h('p', { class: 'muted small', text: 'Observed take-offs only (local time).' }), barChart(Array.from({ length: 24 }, (_, i) => String(i)), Array.from({ length: 24 }, (_, i) => hc[i] || 0), { label: 'Departures per hour', maxLabels: 12 })),\n        h('div', { class: 'card' }, h('h2', { text: 'Destinations' }), hbars(top(count(dep, countryOf), 10))),\n        h('div', { class: 'card' }, h('h2', { text: 'By target' }), hbars(top(count(dep, e => e.targetName || e.targetId), 10))),\n        h('div', { class: 'card' }, h('h2', { text: 'By month' }), months.length ? barChart(months.map(m => MONTHS[Number(m.slice(5)) - 1] + ' ' + m.slice(2, 4)), months.map(m => mc[m]), { label: 'Flights per month' }) : empty('—')),\n        h('div', { class: 'card' }, h('h2', { text: 'Direction' }), hbars(top(count(dep, e => e.direction === 'return' ? 'Return to Torn' : 'Outbound (abroad)'), 2)))));\n      const unk = dep.length - obs.length;\n      box.appendChild(h('div', { class: 'note' }, h('b', { text: 'Read with care. ' }),\n        unk ? unk + ' flight(s) were already underway when the script saw them: they count in the totals but not in the hour, day or gap statistics. ' : '',\n        'Statistics only cover the periods when your script was running (tab open, valid API key): a flight while everything was closed is not recorded. The player’s real online periods are not measured.',\n        S.eventsTruncated ? ' Only the 5,000 most recent events are loaded.' : ''));\n    }\n    function build() {\n      view.appendChild(head('Statistics', 'Your targets\\u2019 flight habits, computed from observed events.'));\n      view.appendChild(filterBar(f, draw, { noType: true }));\n      view.appendChild(box); draw(false);\n    }\n    build();\n  }\n\n  /* ================= PAGE: countries ================= */\n  function countries() {\n    const f = FILTERS.countries, box = h('div');\n    function draw() {\n      clear(box);\n      const dep = applyFilters(S.events, f).filter(e => e.type === 'departure' && e.country);\n      const by = {}; dep.forEach(e => { (by[e.country] = by[e.country] || []).push(e); });\n      const rows = Object.entries(by).map(([c, list]) => { const m = list.filter(e => e.durationMin != null).map(e => e.durationMin);\n        return { country: c, trips: list.length, share: Math.round(list.length / dep.length * 100), targets: Object.keys(count(list, e => e.targetId)).length, last: Math.max.apply(null, list.map(e => e.observedAt)), out: list.filter(e => e.direction !== 'return').length, back: list.filter(e => e.direction === 'return').length, avg: avg(m) }; });\n      if (!rows.length) { box.appendChild(h('div', { class: 'card' }, empty('No countries', 'No flights match these filters.'))); return; }\n      box.appendChild(h('div', { class: 'grid cols-2' },\n        h('div', { class: 'card' }, h('h2', { text: 'Flight distribution' }), hbars(rows.sort((a, b) => b.trips - a.trips).slice(0, 12).map(r => [r.country, r.trips]))),\n        h('div', { class: 'card' }, h('h2', { text: 'Outbound vs return' }), hbars(rows.slice(0, 12).map(r => [r.country + ' (out)', r.out])), h('div', { style: 'height:8px' }), hbars(rows.slice(0, 12).map(r => [r.country + ' (back)', r.back])))));\n      box.appendChild(h('div', { style: 'margin-top:16px' }, dataTable({ rows, defaultSort: 'trips', cols: [\n        { key: 'country', label: 'Country', sortVal: r => r.country, render: r => h('b', { text: flag(r.country) + r.country }) },\n        { key: 'trips', label: 'Flights' }, { key: 'share', label: 'Share', render: r => r.share + ' %' },\n        { key: 'out', label: 'Outbound' }, { key: 'back', label: 'Return' }, { key: 'targets', label: 'Targets' },\n        { key: 'avg', label: 'Avg. duration', render: r => dur(r.avg) }, { key: 'last', label: 'Last flight', render: r => dFmt(r.last) }] }).el));\n    }\n    view.appendChild(head('Country analysis', 'Where your targets go, and how often.'));\n    view.appendChild(filterBar(f, (full) => { if (full) { clear(view); countries(); } else draw(); }, { noType: true }));\n    view.appendChild(box); draw();\n  }\n\n  /* ================= PAGE: alerts ================= */\n  function alerts() {\n    const a = S.prefs.alerts;\n    view.appendChild(head('Alerts', 'Choose what should notify you. These settings are saved on your account.'));\n    const save = async () => { const r = await api('PUT', '/api/prefs', { prefs: S.prefs }); toast(r.ok ? 'Settings saved.' : (r.data.message || 'Could not save.')); };\n    const sw = (key, label, hint) => h('label', { class: 'switch' }, h('span', {}, h('b', { text: label }), h('div', { class: 'muted small', text: hint })),\n      h('input', { type: 'checkbox', checked: a[key] !== false, onchange: (ev) => { a[key] = ev.target.checked; save(); } }));\n    view.appendChild(h('div', { class: 'card' }, h('h2', { text: 'Event types' }),\n      sw('departure', 'Departure abroad', 'When a target takes off.'), sw('arrival', 'Landing', 'When a target arrives at its destination.'), sw('return', 'Return flight', 'When a target flies back to Torn.')));\n    view.appendChild(h('div', { class: 'card', style: 'margin-top:16px' }, h('h2', { text: 'Muted targets' }), h('p', { class: 'muted small', text: 'Tick a target to stop being alerted about it (its history is still recorded).' }),\n      S.targets.length ? S.targets.map(t => h('label', { class: 'switch' }, h('span', { text: t.name || t.tornId }),\n        h('input', { type: 'checkbox', checked: (a.mute || []).indexOf(String(t.tornId)) >= 0, onchange: (ev) => { const m = new Set((a.mute || []).map(String)); if (ev.target.checked) m.add(String(t.tornId)); else m.delete(String(t.tornId)); a.mute = Array.from(m); save(); } }))) : empty('No targets')));\n    view.appendChild(h('div', { class: 'note info' }, 'Important: notifications and sound are produced by the script inside Torn (HUD settings). These preferences are already saved with your account, but the script does not read them yet — that is the next planned step.'));\n  }\n\n\n  /* ================= PAGE: war ================= */\n  const WAR_RANK = { Traveling: 0, Hospital: 1, Abroad: 2, Jail: 3 };\n  const hhmmSec = (sec) => { const d = new Date(sec * 1000); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };\n  const durTxt = (sec) => { sec = Math.max(0, Math.round(sec)); const hr = Math.floor(sec / 3600), mn = Math.floor(sec % 3600 / 60), sc = sec % 60; return hr ? hr + 'h' + pad(mn) : mn + ':' + pad(sc); };\n  /* ================= PAGE: radar (closed beta) ================= */\n  /* ================= Radar world map (own drawing: dotted land, no external data) ================= */\n  const MAP_W = 1000, MAP_LAT_TOP = 80, MAP_LAT_BOTTOM = -58, MAP_H = Math.round((MAP_LAT_TOP - MAP_LAT_BOTTOM) * MAP_W / 360);\n  const MAP_LAND = [\n    [[-168,65],[-165,69],[-156,71],[-141,70],[-128,70],[-112,68],[-96,68],[-85,69.5],[-82,66],[-70,63],[-65,60],[-62,57],[-56,52],[-60,47],[-66,44],[-70,42],[-74,39],[-76,35],[-81,31],[-80,26],[-82,26],[-84,30],[-89,30],[-94,29],[-97,26],[-98,22],[-96,19],[-91,18.5],[-90,21],[-87,21.5],[-88,16],[-84,15.5],[-83,11],[-80,9],[-77,8.5],[-79,7.5],[-83,8],[-86,11],[-88,13],[-92,14.5],[-96,15.8],[-101,17.5],[-105,20],[-109,25],[-113,30],[-115,32],[-117,32.5],[-120,34.5],[-122,37],[-124,40],[-124,46],[-123,48.5],[-127,51],[-131,55],[-136,58],[-142,60],[-149,60],[-153,58],[-158,56],[-163,55],[-158,58],[-162,60],[-165,62]],\n    [[-73,78],[-60,82],[-30,83],[-18,80],[-20,72],[-24,70],[-40,65],[-43,60],[-50,63],[-54,67],[-58,75]],\n    [[-24,65],[-22,66.5],[-15,66.3],[-13.5,65],[-18,63.4],[-22,64]],\n    [[-77,8.5],[-72,12],[-65,10.5],[-60,8.5],[-52,5],[-50,0],[-44,-2.5],[-35,-5.5],[-35,-9],[-39,-14],[-39,-18],[-41,-22],[-45,-23.5],[-48,-26],[-49,-29],[-53,-34],[-58,-34.5],[-57,-37],[-62,-39],[-65,-41],[-64.5,-43],[-67.5,-46],[-66,-48],[-69,-51],[-68.5,-53],[-71,-54.5],[-74,-52],[-75,-47],[-73.5,-40],[-71.5,-30],[-70.5,-20],[-76,-14],[-81,-6],[-80,-2],[-80,1],[-77,4],[-77.5,7]],\n    [[-9,37],[-9,43],[-2,43.5],[-1.5,46],[-4.5,48.5],[2,51],[5,53.5],[8.5,55],[8,57],[10.5,57.7],[10.5,54.5],[14,54.2],[19,54.5],[21,57],[24,57.5],[24,59.5],[29,60],[22,60.5],[21.5,63],[25,65],[21,65.5],[17.5,62.5],[19,60],[16.5,56.5],[13,55.5],[11,59],[8,58],[5,59],[5,62],[14,67],[20,70],[28,71],[40,67],[44,68],[60,69],[68,69],[75,72],[80,73],[100,76.5],[113,74],[128,72],[140,72.5],[160,70],[170,70],[180,68.5],[180,65],[170,60],[163,56],[157,51],[155,56.5],[150,59.5],[143,59],[137,54],[141,52],[140,47],[135,43],[130,42.5],[129.5,40],[127.5,39.5],[129,36],[126.5,34.5],[126,37.5],[125,39.5],[121.5,39],[121,40.8],[118,39],[119,37.2],[122.5,37],[120,35],[121.5,32],[122,30],[120,26],[117,23.5],[114,22.3],[110,21],[108,21.5],[106.5,19],[109,15],[109.2,12],[105,8.7],[105,10.5],[101,13],[99.5,10],[101,6.5],[103.5,1.5],[100.5,3.5],[98,8],[98.5,13],[97.5,16.5],[94.5,16],[94,19],[92,21.5],[90,22],[86.5,20],[84,18],[80,15],[80,10],[77.5,8],[76,10],[73,17],[72.5,21],[70,21],[67,24.5],[62,25],[57,25.5],[56.5,27],[51,28],[48.5,30],[50,26.5],[51.5,24.5],[54,24],[56,26],[57,23.5],[59,22.5],[55,17],[52,16],[45,13],[43,13],[42.5,16],[39,21],[35,28],[34.8,31.5],[36,34.5],[36,36.5],[30,36.3],[27,37],[26.2,40],[23,40.2],[22.7,36.5],[21.3,37.8],[19.5,41.5],[15,44.5],[13.7,45.6],[8,44],[7,43.5],[3,43.2],[3,42],[0.5,40.5],[-0.5,38.5],[-2,36.8],[-5.5,36]],\n    [[12.3,45.5],[13.7,45.6],[12.5,43.5],[16,41.8],[18.5,40.2],[16.5,38.5],[15.7,38],[15.8,40],[13,41.2],[10.5,43.5],[8.8,44.4],[7,43.7]],\n    [[-17.5,14.7],[-16.5,19],[-13,27.5],[-10,29.5],[-9.5,32],[-6,35.8],[-2,35.2],[3,36.8],[10,37.2],[11,33.5],[15,32.2],[20,32.5],[20,31],[25,31.7],[32,31.2],[34,28.5],[32.5,29.5],[35,24],[37.5,18.5],[39,15.5],[43,12.5],[44,10.5],[51,11.8],[51,10],[48,5],[42,-1],[40,-4],[39,-8],[40.5,-11],[40.5,-15],[35,-20],[35.5,-24],[32.5,-26],[32.5,-28.5],[30,-31.5],[26,-34],[20,-34.8],[18.3,-34],[18,-30],[15,-27],[14.5,-22],[12,-17],[13.5,-12],[12,-6],[9,-1],[9.5,3.5],[6,4.3],[3,6.3],[-2,5],[-7.5,4.4],[-12,7.5],[-15,11],[-17,13.5]],\n    [[44,-25],[47,-25],[50,-15.5],[49.5,-12.2],[48,-13.5],[44,-17],[43.5,-22]],\n    [[114,-22],[114,-26],[115,-34],[118,-35],[123,-34],[130,-31.5],[135,-35],[138,-35],[140,-38],[146,-39],[150,-37],[153,-31],[153,-26],[149,-20],[146,-18.5],[145,-14.5],[143,-11],[142.5,-14],[141,-17],[136,-15],[135,-12],[131,-11.5],[129,-15],[126,-14],[122,-17.5]],\n    [[172.5,-34.5],[178,-37.7],[175,-41.5],[174.5,-41.5]], [[172.8,-40.6],[174,-41.5],[171,-44.5],[168,-46.5],[166.5,-45.5],[170,-43]],\n    [[-5.5,50],[1.5,51],[1.7,52.8],[-0.5,54],[-1.5,55.5],[-2,57.5],[-3.5,58.6],[-5.5,58.5],[-6,56.5],[-5,55],[-3,54.8],[-3,53.4],[-4.5,53.2],[-5,51.7],[-3.5,51.3]],\n    [[-10,52],[-6,52.2],[-6,54.5],[-8,55.2],[-10,54]],\n    [[133,33.5],[133,35.5],[136,36],[137,37],[140,40],[141.5,41.5],[142,39.5],[141,36],[140,35],[137,34.6],[135,33.7]], [[140,42],[141,45.4],[145,44],[143,42]], [[129.8,33],[131.5,33.5],[131.5,31.2],[130.2,31]],\n    [[95,5.5],[98,4],[104,-1],[106,-3],[105.5,-6],[101,-3],[96,2]], [[109,1.5],[111,2],[115,5],[117.5,7],[119,5],[117.5,1],[116,-3.5],[111,-3],[110,-1]], [[105.5,-6.8],[108,-6.5],[114.5,-7.8],[114,-8.7],[106,-7.5]],\n    [[131,-1],[135,-3.3],[141,-2.6],[145,-5],[148,-6],[150.5,-10.5],[147,-10],[143,-9],[141,-9],[138,-8],[137,-5],[133,-4]],\n    [[120,18.5],[122,18],[122,14],[124,12.5],[126,9],[125.5,6],[122,7],[123.5,10],[120.5,14]], [[120.2,22.5],[121.5,25],[122,24.5],[120.9,22]],\n    [[-85,22],[-82,23.2],[-77,21.5],[-74.2,20.2],[-78,20],[-81,22]], [[-74.4,18.5],[-72,19.9],[-68.4,18.6],[-71,17.8]], [[80,9.8],[81.8,7.5],[80.5,6],[79.8,8]]\n  ];\n  const MAP_WATER = [   // inland seas cut out of the land\n    [[-94,59],[-93,56],[-88,55.5],[-82,53],[-79,51.5],[-78.5,55],[-77,59],[-78,62],[-85,64],[-90,64],[-94,62]],\n    [[28,41.5],[28,44],[30,46],[33,46],[36,45],[41,42],[41,41],[36,41.5],[31,41.2]],\n    [[47,45],[50,46.5],[53,45],[53.5,40],[54,37],[50,37],[49,40],[47,43]]\n  ];\n  const MAP_TORN = { lon: -80, lat: 39 };\n  const MAP_PLACES = {   // Torn destinations (real-world positions are enough for a fun picture)\n    'Mexico': { lon: -102, lat: 23, dx: -9, dy: 14, a: 'end' }, 'Cayman Islands': { lon: -81, lat: 19, dx: 9, dy: 15, a: 'start' },\n    'Canada': { lon: -100, lat: 55, dx: 0, dy: -11, a: 'middle' }, 'Hawaii': { lon: -157, lat: 20.5, dx: 0, dy: -11, a: 'middle' },\n    'United Kingdom': { lon: -1.5, lat: 53, dx: -9, dy: -4, a: 'end' }, 'Argentina': { lon: -64, lat: -34, dx: 10, dy: 4, a: 'start' },\n    'Switzerland': { lon: 8, lat: 46.8, dx: 9, dy: 14, a: 'start' }, 'Japan': { lon: 138, lat: 36, dx: 9, dy: 4, a: 'start' },\n    'China': { lon: 104, lat: 34, dx: 0, dy: 15, a: 'middle' }, 'United Arab Emirates': { lon: 54, lat: 24, dx: 0, dy: 15, a: 'middle' },\n    'South Africa': { lon: 24, lat: -29, dx: 9, dy: 4, a: 'start' }\n  };\n  const mapX = (lon) => (((lon + 180) % 360) + 360) % 360 * MAP_W / 360;\n  const mapY = (lat) => (MAP_LAT_TOP - lat) * MAP_W / 360;\n  function mapInside(poly, x, y) {\n    let c = false;\n    for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {\n      const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];\n      if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) c = !c;\n    }\n    return c;\n  }\n  let MAP_DOTS = null;\n  function mapDots() {\n    if (MAP_DOTS) return MAP_DOTS;\n    const step = 2.8; let d = '';\n    for (let lat = MAP_LAT_TOP - 1; lat > MAP_LAT_BOTTOM; lat -= step) {\n      for (let lon = -179; lon < 180; lon += step) {\n        if (MAP_LAND.some(p => mapInside(p, lon, lat)) && !MAP_WATER.some(p => mapInside(p, lon, lat))) d += 'M' + mapX(lon).toFixed(1) + ' ' + mapY(lat).toFixed(1) + 'h0';\n      }\n    }\n    return (MAP_DOTS = d);\n  }\n  // Point on the curved route Torn -> destination at t (0..1): shortest way round the globe, bulging north.\n  function mapRoute(place, t) {\n    let dlon = place.lon - MAP_TORN.lon; dlon = ((dlon + 540) % 360) - 180;\n    const dlat = place.lat - MAP_TORN.lat, bulge = 0.16 * Math.hypot(dlon, dlat);\n    return { lon: MAP_TORN.lon + dlon * t, lat: MAP_TORN.lat + dlat * t + bulge * Math.sin(Math.PI * t) };\n  }\n  function mapPath(place) {\n    let d = '', prev = null;\n    for (let i = 0; i <= 56; i++) {\n      const p = mapRoute(place, i / 56), x = mapX(p.lon), y = mapY(p.lat);\n      d += (prev === null || Math.abs(x - prev) > 400 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1);\n      prev = x;\n    }\n    return d;\n  }\n  // t is progress from Torn; dir 'return' flies the same route backwards.\n  function mapPlanePos(place, t, back) {\n    const p = mapRoute(place, t), q = mapRoute(place, Math.min(1, Math.max(0, t + (back ? -0.015 : 0.015))));\n    const ux = (q.lon - p.lon) * MAP_W / 360, uy = -(q.lat - p.lat) * MAP_W / 360;\n    return { x: mapX(p.lon), y: mapY(p.lat), deg: Math.atan2(uy, ux) * 180 / Math.PI };\n  }\n  const MAP_ICONS = {   // all drawn pointing right, about 14 units long\n    airliner: 'M7 0L1.2-1.3-2-6.5-3.6-6.5-2.2-1.1-5-.9-6-3.3-7.2-3.3-6.4 0-7.2 3.3-6 3.3-5 .9-2.2 1.1-3.6 6.5-2 6.5 1.2 1.3Z',\n    light: 'M6 0L3.2-1 2.4-5.2.6-5.2.8-1-3-.8-4.6-2.6-5.6-2.6-4.8 0-5.6 2.6-4.6 2.6-3 .8.8 1 .6 5.2 2.4 5.2 3.2 1Z',\n    jet: 'M9 0L3-.9-1.5-5.8-3.3-5.8-2-.9-5.2-.7-6.8-3-7.8-3-7 0-7.8 3-6.8 3-5.2.7-2 .9-3.3 5.8-1.5 5.8 3 .9Z',\n    biz: 'M8 0L1.4-1.5-2.2-7.4-4.2-7.4-2.5-1.3-5.8-1-6.9-3.8-8.3-3.8-7.4 0-8.3 3.8-6.9 3.8-5.8 1-2.5 1.3-4.2 7.4-2.2 7.4 1.4 1.5Z'\n  };\n  const MAP_KIND_NAMES = { airliner: 'Standard (airliner)', light: 'Airstrip (light aircraft)', jet: 'WLT (private jet)', biz: 'Business' };\n  function mapKind(plane) {\n    const p = String(plane || '').toLowerCase();\n    if (/airstrip|light/.test(p)) return 'light';\n    if (/wlt|jet|private/.test(p)) return 'jet';\n    if (/business/.test(p)) return 'biz';\n    return 'airliner';\n  }\n  // Hot spot = at least 3 aircraft going out to the same country and due to land within 3 minutes of each other.\n  function mapHotSpots(flying) {\n    const by = {}, hot = {};\n    flying.forEach(f => { if (f.direction !== 'return' && f.landingAt > 0 && f.country) (by[f.country] = by[f.country] || []).push(f.landingAt); });\n    Object.keys(by).forEach(c => { const a = by[c].sort((x, y) => x - y); for (let i = 0; i + 2 < a.length; i++) if (a[i + 2] - a[i] <= 180) { hot[c] = a[i]; break; } });\n    return hot;\n  }\n  // opts: { sel: {t:'c'|'p', k}, onSelect(sel) }.  Hover shows a tooltip, click selects.\n  function radarMap(d, opts) {\n    opts = opts || {};\n    const ns = 'http://www.w3.org/2000/svg', flying = d.flying || [];\n    const skew = (d.now || 0) - Math.floor(Date.now() / 1000);\n    const wrap = h('div', { class: 'rmapwrap' });\n    const tip = h('div', { class: 'rmap-tip', role: 'tooltip' }); tip.style.display = 'none';\n    const svg = document.createElementNS(ns, 'svg');\n    svg.setAttribute('viewBox', '0 0 ' + MAP_W + ' ' + MAP_H); svg.setAttribute('class', 'rmap'); svg.setAttribute('role', 'group');\n    svg.setAttribute('aria-label', 'World map with the aircraft of the followed players. Click a plane or a country for details.');\n    wrap.appendChild(svg); wrap.appendChild(tip);\n    const mk = (tag, a, parent, t) => { const e = document.createElementNS(ns, tag); for (const k in a) e.setAttribute(k, a[k]); if (t != null) e.textContent = t; (parent || svg).appendChild(e); return e; };\n    const isSel = (t, k) => !!(opts.sel && opts.sel.t === t && opts.sel.k === k);\n    const eta = (f) => f.landingAt > 0 ? new Date(f.landingAt * 1000).toTimeString().slice(0, 5) : null;\n    function showTip(ev, lines) {\n      tip.textContent = ''; lines.forEach((l, i) => tip.appendChild(h(i ? 'div' : 'b', { text: l })));\n      tip.style.display = 'block';\n      const r = wrap.getBoundingClientRect(); let x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 14;\n      if (x + tip.offsetWidth > r.width - 4) x = ev.clientX - r.left - tip.offsetWidth - 14;\n      if (y + tip.offsetHeight > r.height - 4) y = ev.clientY - r.top - tip.offsetHeight - 14;\n      tip.style.left = Math.max(2, x) + 'px'; tip.style.top = Math.max(2, y) + 'px';\n    }\n    const hide = () => { tip.style.display = 'none'; };\n    function interactive(el, sel, lines, label) {\n      el.setAttribute('tabindex', '0'); el.setAttribute('role', 'button'); el.setAttribute('aria-label', label);\n      el.addEventListener('mousemove', ev => showTip(ev, lines()));\n      el.addEventListener('mouseleave', hide);\n      el.addEventListener('focus', () => { const b = el.getBoundingClientRect(), r = wrap.getBoundingClientRect(); showTip({ clientX: b.left + b.width / 2, clientY: b.top }, lines()); });\n      el.addEventListener('blur', hide);\n      const pick = () => { hide(); if (opts.onSelect) opts.onSelect(sel); };\n      el.addEventListener('click', pick);\n      el.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });\n    }\n    mk('path', { d: mapDots(), class: 'land' });\n    const hot = mapHotSpots(flying);\n    const by = {};\n    flying.forEach(f => { if (MAP_PLACES[f.country]) (by[f.country] = by[f.country] || []).push(f); });\n    Object.keys(MAP_PLACES).forEach(name => {\n      const pl = MAP_PLACES[name], list = by[name] || [], out = list.filter(f => f.direction !== 'return').length, back = list.length - out, x = mapX(pl.lon), y = mapY(pl.lat);\n      if (list.length) mk('path', { d: mapPath(pl), class: 'route' + (hot[name] ? ' hotroute' : '') });\n      if (hot[name]) mk('circle', { cx: x, cy: y, r: 10, class: 'pulse' });\n      const g = mk('g', { class: 'destg' + (isSel('c', name) ? ' sel' : '') });\n      mk('circle', { cx: x, cy: y, r: 13, class: 'hit' }, g);\n      mk('circle', { cx: x, cy: y, r: list.length ? 4.5 : 3, class: 'dest' + (list.length ? ' on' : '') }, g);\n      const label = mk('text', { x: x + pl.dx, y: y + pl.dy, 'text-anchor': pl.a, class: 'lbl' + (list.length ? ' on' : '') + (hot[name] ? ' hot' : '') }, g, name + (list.length ? ' ' + (out ? '↗' + out : '') + (back ? ' ↙' + back : '') : ''));\n      interactive(g, { t: 'c', k: name }, () => {\n        const ls = [name, out + ' going out · ' + back + ' coming back'];\n        const lands = list.filter(f => f.landingAt > 0).map(f => f.landingAt).sort((a, b) => a - b);\n        if (lands.length) ls.push('first landing ~' + hhmmSec(lands[0]));\n        if (hot[name]) ls.push('Hot spot: 3+ landing within 3 min');\n        return ls;\n      }, name + ', ' + list.length + ' flying');\n    });\n    const hx = mapX(MAP_TORN.lon), hy = mapY(MAP_TORN.lat);\n    mk('circle', { cx: hx, cy: hy, r: 8, class: 'home' }); mk('circle', { cx: hx, cy: hy, r: 3, class: 'homedot' });\n    mk('text', { x: hx - 11, y: hy + 15, 'text-anchor': 'end', class: 'lbl on' }, null, 'Torn');\n    // aircraft: the 60 closest to landing; unknown take-off = faint dot on the route\n    const near = flying.filter(f => MAP_PLACES[f.country]).sort((a, b) => (a.landingAt || 9e12) - (b.landingAt || 9e12)).slice(0, 60);\n    const items = near.map(f => {\n      const pl = MAP_PLACES[f.country], back = f.direction === 'return', known = f.takeoffAt > 0 && f.duration > 0, kind = mapKind(f.plane);\n      const g = mk('g', { class: (known ? 'plane k-' + kind + (back ? ' back' : '') : 'gh') + (isSel('p', f.id) ? ' sel' : '') });\n      mk('circle', { r: 11, class: 'hit' }, g);\n      if (isSel('p', f.id)) mk('circle', { r: 11, class: 'selring' }, g);\n      if (known) mk('path', { d: MAP_ICONS[kind], transform: 'scale(' + (kind === 'light' ? 1.3 : kind === 'biz' ? 1.1 : 1.2) + ')' }, g); else mk('circle', { r: 3.5, class: 'ghostdot' }, g);\n      interactive(g, { t: 'p', k: f.id }, () => {\n        const now = Math.floor(Date.now() / 1000) + skew;\n        return [(f.name || '#' + f.id) + (f.position ? ' · ' + f.position : ''), (back ? '← Torn from ' : '→ ') + f.country + ' · ' + (f.plane || 'aircraft unknown'),\n          known ? (f.landingAt > now ? 'lands ~' + hhmmSec(f.landingAt) + ' (in ' + durTxt(f.landingAt - now) + ')' : 'about to land') : 'take-off unknown, landing unknown'];\n      }, (f.name || '#' + f.id) + ' flying to ' + f.country);\n      return { f, pl, back, known, g, ghostT: 0.3 + ((Number(f.id) || 1) % 41) / 100 };\n    });\n    function place() {\n      const now = Math.floor(Date.now() / 1000) + skew;\n      items.forEach(it => {\n        const prog = it.known ? Math.min(0.985, Math.max(0.01, (now - it.f.takeoffAt) / it.f.duration)) : it.ghostT;\n        const t = it.back ? 1 - prog : prog, p = mapPlanePos(it.pl, t, it.back);\n        it.g.setAttribute('transform', 'translate(' + p.x.toFixed(1) + ' ' + p.y.toFixed(1) + ') rotate(' + p.deg.toFixed(0) + ')');\n        const hit = it.g.firstChild; if (hit) hit.setAttribute('transform', 'rotate(' + (-p.deg).toFixed(0) + ')');\n      });\n    }\n    place();\n    const timer = setInterval(() => { if (!wrap.isConnected) { clearInterval(timer); return; } place(); }, 1000);\n    return wrap;\n  }\n\n  let RADAR_TAB = 'map', RADAR_SEL = null;\n  let RADAR_MIN_SCORE = 70, RADAR_MIN_PLAYERS = 3, RADAR_ST_COUNTRY = '', RADAR_ST_PROFIT = true, RADAR_ST_STOCKED = false;\n  try { const a = Number(localStorage.getItem('ts_radar_min_score')), b = Number(localStorage.getItem('ts_radar_min_players')); if (a >= 0 && a <= 100 && localStorage.getItem('ts_radar_min_score') !== null) RADAR_MIN_SCORE = a; if (b >= 2 && b <= 10) RADAR_MIN_PLAYERS = b; } catch (e) {}\n  const saveRadarPrefs = () => { try { localStorage.setItem('ts_radar_min_score', String(RADAR_MIN_SCORE)); localStorage.setItem('ts_radar_min_players', String(RADAR_MIN_PLAYERS)); } catch (e) {} };\n  function svgIcon(kind) {\n    const e = document.createElement('span'); e.className = 'lg-ico';\n    e.innerHTML = '<svg viewBox=\"-9 -8 18 16\" width=\"18\" height=\"16\" aria-hidden=\"true\"><path d=\"' + MAP_ICONS[kind] + '\"/><\/svg>'; return e;\n  }\n  /* ================= Travel stock: planner maths + charts ================= */\n  const PLAN_DEFAULT = { type: 'airstrip', carry: 27, cash: 0, sell: 95, buffer: 60, countries: null, types: null, q: '', profitOnly: true, stockedOnly: false, horizon: 8, view: 'items', tz: 'local', range: '24h' };\n  let RADAR_PLAN = Object.assign({}, PLAN_DEFAULT);\n  try { const raw = localStorage.getItem('ts_plan'); if (raw) { const o = JSON.parse(raw); if (o && typeof o === 'object') RADAR_PLAN = Object.assign({}, PLAN_DEFAULT, o); } } catch (e) {}\n  const savePlan = () => { try { localStorage.setItem('ts_plan', JSON.stringify(RADAR_PLAN)); } catch (e) {} };\n  const PLAN_TYPES = [['standard', 'Std', 'Standard'], ['airstrip', 'Air', 'Airstrip'], ['wlt', 'WLT', 'WLT'], ['business', 'Biz', 'Business']];\n  const PLAN_GROUPS = [['Short', ['Mexico', 'Cayman Islands', 'Canada']], ['Medium', ['Hawaii', 'United Kingdom', 'Argentina', 'Switzerland']], ['Long', ['Japan', 'China', 'United Arab Emirates', 'South Africa']]];\n  const fmtDur = (sec) => { sec = Math.max(0, Math.round(sec)); const hr = Math.floor(sec / 3600), mn = Math.floor(sec % 3600 / 60); return hr ? hr + 'h ' + pad(mn) + 'm' : mn ? mn + 'm' : sec + 's'; };\n  // One row per country/item with what a trip would earn. now = unix seconds.\n  function planRows(ST, P, now) {\n    const out = [], q = String(P.q || '').trim().toLowerCase();\n    (ST.countries || []).forEach(c => {\n      if (P.countries && P.countries.indexOf(c.name) < 0) return;\n      const dur = (ST.travelSec && ST.travelSec[c.name] && ST.travelSec[c.name][P.type]) || 0; if (!dur) return;\n      c.items.forEach(i => {\n        if (P.types && P.types.indexOf(i.type || 'Other') < 0) return;\n        if (q && i.name.toLowerCase().indexOf(q) < 0) return;\n        const pu = i.market > 0 ? Math.round(i.market * P.sell / 100) - i.cost : null;\n        const afford = P.cash > 0 ? Math.floor(P.cash / Math.max(1, i.cost)) : P.carry;\n        const rate = i.depletionNow > 0 ? i.depletionNow : (i.depletionMed || 0);\n        const land = now + dur;\n        const qtyLand = i.qty > 0 ? (rate > 0 ? Math.max(0, Math.floor(i.qty - rate * dur / 60)) : i.qty) : 0;\n        const soldBy = i.qty > 0 && ((i.emptiesAt > 0 && land >= i.emptiesAt) || qtyLand === 0);\n        const leaveAt = i.nextRestockAt > 0 ? i.nextRestockAt + P.buffer - dur : 0;\n        let avail = 'none', units = 0, departAt = 0;\n        if (i.qty > 0 && !soldBy) { avail = 'now'; units = Math.min(P.carry, afford, qtyLand); departAt = now; }\n        else if (i.nextRestockAt > 0) { avail = 'restock'; units = Math.min(P.carry, afford, i.restockQty > 0 ? i.restockQty : P.carry); departAt = Math.max(now, leaveAt); }\n        else if (i.qty > 0) avail = 'late';\n        const perHour = pu > 0 && units > 0 ? Math.round(units * pu / (2 * dur / 3600)) : 0;\n        out.push(Object.assign({}, i, { country: c.name, code: c.code, key: c.code + '|' + i.id, dur, pu, avail, units, departAt, leaveAt, perHour, qtyLand, rate, tripProfit: pu > 0 ? units * pu : 0 }));\n      });\n    });\n    return out;\n  }\n  // Greedy day plan: always take the trip that earns the most per hour of elapsed time (waiting included).\n  function dayPlan(rows, P, now) {\n    const end = now + P.horizon * 3600, used = {}, trips = [];\n    let t = now;\n    while (trips.length < 14) {\n      let best = null;\n      rows.forEach(r => {\n        if (used[r.key] || r.units <= 0 || !(r.pu > 0)) return;\n        let depart;\n        if (r.avail === 'now') { if (t > now + 60 && !(r.emptiesAt > 0 && t + r.dur < r.emptiesAt)) return; depart = t; }\n        else depart = Math.max(t, r.nextRestockAt + P.buffer - r.dur);\n        const back = depart + 2 * r.dur; if (back > end) return;\n        const score = r.units * r.pu / (back - t);\n        if (!best || score > best.score) best = { r, depart, land: depart + r.dur, back, score };\n      });\n      if (!best) break;\n      trips.push(best); used[best.r.key] = true; t = best.back;\n    }\n    return { trips, total: trips.reduce((a, x) => a + x.r.units * x.r.pu, 0) };\n  }\n  const compact = (n, money) => { const a = Math.abs(n), p = money ? '$' : ''; return a >= 1e9 ? p + (n / 1e9).toFixed(1) + 'B' : a >= 1e6 ? p + (n / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M' : a >= 1e3 ? p + (n / 1e3).toFixed(a >= 1e5 ? 0 : 1).replace(/\\.0$/, '') + 'K' : p + Math.round(n); };\n  // Step / line chart. o = { points:[[t,v]], x0, x1, nowT, yMin, yMax, step, yFmt, xFmt, markers:[{t,cls}], forecast:[[t,v]], tip(t,v), cls, label, h }\n  function lineChart(o) {\n    const ns = 'http://www.w3.org/2000/svg', W = 900, H = o.h || 210, L = 52, R = 16, T = 14, B = 26;\n    const svg = document.createElementNS(ns, 'svg');\n    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('class', 'tchart'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', o.label || 'Chart');\n    const el = (tag, a, t) => { const e = document.createElementNS(ns, tag); for (const k in a) e.setAttribute(k, a[k]); if (t != null) e.textContent = t; svg.appendChild(e); return e; };\n    const all = o.points.concat(o.forecast || []);\n    let lo = o.yMin != null ? o.yMin : 0, hi = o.yMax != null ? o.yMax : Math.max.apply(null, all.map(p => p[1]).concat([1])) * 1.08;\n    if (o.yMin == null && o.autoMin && all.length) { lo = Math.min.apply(null, all.map(p => p[1])); hi = Math.max.apply(null, all.map(p => p[1])); const pad2 = (hi - lo) * .15 || hi * .01 || 1; lo -= pad2; hi += pad2; }\n    const X = (t) => L + (t - o.x0) / Math.max(1, o.x1 - o.x0) * (W - L - R), Y = (v) => T + (1 - (v - lo) / Math.max(1e-9, hi - lo)) * (H - T - B);\n    for (let i = 0; i <= 3; i++) { const v = lo + (hi - lo) * i / 3, y = Y(v); el('line', { x1: L, x2: W - R, y1: y, y2: y, class: 'tgrid' }); el('text', { x: L - 6, y: y + 4, 'text-anchor': 'end' }, o.yFmt(v)); }\n    for (let i = 0; i <= 5; i++) { const t = o.x0 + (o.x1 - o.x0) * i / 5; el('text', { x: X(t), y: H - 7, 'text-anchor': i === 0 ? 'start' : i === 5 ? 'end' : 'middle' }, o.xFmt(t)); }\n    const pts = o.points;\n    if (pts.length) {\n      let d = 'M' + X(pts[0][0]).toFixed(1) + ',' + Y(pts[0][1]).toFixed(1);\n      for (let i = 1; i < pts.length; i++) d += o.step ? ' H' + X(pts[i][0]).toFixed(1) + ' V' + Y(pts[i][1]).toFixed(1) : ' L' + X(pts[i][0]).toFixed(1) + ',' + Y(pts[i][1]).toFixed(1);\n      const endX = X(Math.min(o.nowT || o.x1, o.x1)); d += ' H' + endX.toFixed(1);\n      el('path', { d: d + ' V' + Y(lo).toFixed(1) + ' H' + X(pts[0][0]).toFixed(1) + ' Z', class: 'tarea ' + (o.cls || '') });\n      el('path', { d, class: 'tline ' + (o.cls || '') });\n    }\n    (o.markers || []).forEach(m => { if (m.t >= o.x0 && m.t <= o.x1) { const x = X(m.t); el('line', { x1: x, x2: x, y1: T, y2: H - B, class: 'tmk ' + m.cls }); if (m.text) el('text', { x: x - 4, y: T + 10, 'text-anchor': 'end', class: 'tmk-t' }, m.text); } });\n    if (o.forecast && o.forecast.length > 1) el('polyline', { points: o.forecast.map(p => X(p[0]).toFixed(1) + ',' + Y(p[1]).toFixed(1)).join(' '), class: 'tfc' });\n    const wrap = h('div', { class: 'tchartwrap' }), tip = h('div', { class: 'ttip', hidden: true });\n    const hit = el('rect', { x: L, y: T, width: W - L - R, height: H - T - B, fill: 'transparent' });\n    hit.addEventListener('mousemove', (ev) => {\n      const r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) / r.width * W, t = o.x0 + (px - L) / (W - L - R) * (o.x1 - o.x0);\n      let p = null; for (let i = 0; i < pts.length; i++) { if (pts[i][0] <= t) p = pts[i]; else break; }\n      if (!p) { tip.hidden = true; return; }\n      tip.textContent = o.tip(t, p[1]); tip.hidden = false; tip.style.left = Math.min(r.width - 150, Math.max(0, ev.clientX - r.left + 10)) + 'px'; tip.style.top = '4px';\n    });\n    hit.addEventListener('mouseleave', () => { tip.hidden = true; });\n    wrap.appendChild(svg); wrap.appendChild(tip);\n    return wrap;\n  }\n\n  async function radarPage() {\n    view.appendChild(head('Restock radar', 'Beta. Cruise Line employees: who is flying where, with which aircraft, and when they should land.'));\n    if (!(S.me && S.me.beta)) { view.appendChild(h('div', { class: 'card' }, empty('Not available', 'This page is not open yet.'))); return; }\n    const box = h('div'); view.appendChild(box);\n    let timer = null, infoTimer = null, loadedAt = Date.now();\n    const hm = (sec) => sec ? hhmmSec(sec) : '—';\n    const place = (c, dir) => (dir === 'return' ? '← Torn from ' : '→ ') + (c || '?');\n    async function load() {\n      const [r, ri, rs] = await Promise.all([api('GET', '/api/radar'), api('GET', '/api/radar/insights'), api('GET', '/api/radar/stock')]);\n      loadedAt = Date.now();\n      const keepY = window.scrollY;\n      clear(box);\n      if (!r.ok) { box.appendChild(h('div', { class: 'card' }, empty('Radar unavailable', r.data && r.data.message || ''))); return; }\n      const d = r.data, st = d.stats, now = d.now;\n      const I = ri.ok ? ri.data : null;\n      const ST = rs.ok ? rs.data : null;\n      const sigList = () => !I ? [] : I.clusters.map(c => { const good = c.members.filter(m => m.score >= RADAR_MIN_SCORE); return Object.assign({}, c, { good, avg: good.length ? Math.round(good.reduce((a, m) => a + m.score, 0) / good.length) : 0 }); }).filter(c => c.good.length >= RADAR_MIN_PLAYERS);\n      box.appendChild(h('div', { class: 'grid cols-4' },\n        stat('Employees followed', String(st.players), st.activeCompanies + ' companies'),\n        stat('Flying now', String(st.flying)),\n        stat('Flights recorded', String(st.flights), st.flights24h + ' in the last 24 h'),\n        stat('Landings seen', String(st.landed), st.lastReadAt ? 'last read ' + ago(st.lastReadAt) : 'no read yet')));\n      const P = { map: h('div'), signals: h('div'), players: h('div'), stock: h('div'), dest: h('div'), flying: h('div'), history: h('div') };\n      const tabDefs = [['map', 'Live map'], ['signals', 'Signals (' + sigList().length + ')'], ['players', 'Players' + (I ? ' (' + I.players.length + ')' : '')], ['stock', 'Stock'], ['dest', 'By destination (' + d.countries.length + ')'], ['flying', 'Flying now (' + d.flying.length + ')'], ['history', 'Latest flights']];\n      const bar = h('div', { class: 'rtabs', role: 'tablist' });\n      const show = () => { tabDefs.forEach(([k], i) => { P[k].style.display = k === RADAR_TAB ? '' : 'none'; bar.children[i].setAttribute('aria-selected', String(k === RADAR_TAB)); bar.children[i].className = 'rtab' + (k === RADAR_TAB ? ' on' : ''); }); };\n      tabDefs.forEach(([k, label]) => bar.appendChild(h('button', { class: 'rtab', role: 'tab', onclick: () => { RADAR_TAB = k; show(); } }, label)));\n      box.appendChild(bar); ['map', 'signals', 'players', 'stock', 'dest', 'flying', 'history'].forEach(k => { P[k].style.marginTop = '14px'; box.appendChild(P[k]); });\n      const cnt = (c) => d.flying.filter(f => f.country === c).length;\n      const infoBox = h('div', { class: 'rmap-info' });\n      const mapEl = () => radarMap(d, { sel: RADAR_SEL, onSelect: (sel) => { RADAR_SEL = (RADAR_SEL && RADAR_SEL.t === sel.t && RADAR_SEL.k === sel.k) ? null : sel; drawMap(); } });\n      const mapHost = h('div');\n      function drawMap() { clear(mapHost); mapHost.appendChild(mapEl()); drawInfo(); }\n      function drawInfo() {\n        clear(infoBox);\n        const nowS = Math.floor(Date.now() / 1000) + (d.now - Math.floor(loadedAt / 1000));\n        const sel = RADAR_SEL;\n        if (!sel) { infoBox.appendChild(h('p', { class: 'muted small', text: 'Hover an aircraft or a country for a quick look, click for the details. Click again to close.' })); return; }\n        if (sel.t === 'p') {\n          const f = d.flying.find(x => x.id === sel.k);\n          if (!f) { infoBox.appendChild(h('p', { class: 'muted small', text: 'This player is not flying any more.' })); return; }\n          const back = f.direction === 'return', known = f.takeoffAt > 0 && f.duration > 0;\n          const prog = known ? Math.max(0, Math.min(100, Math.round(100 * (nowS - f.takeoffAt) / f.duration))) : null;\n          infoBox.appendChild(h('div', { class: 'row', style: 'justify-content:space-between;align-items:flex-start' },\n            h('div', null, h('h3', { text: (f.name || '#' + f.id) + (f.position ? ' · ' + f.position : '') }), h('p', { class: 'muted small', text: (f.company || '') + ' [' + f.id + ']' })),\n            h('span', { class: 'badge ' + (back ? 'acc' : 'info'), text: (back ? '← Torn from ' : '→ ') + f.country })));\n          infoBox.appendChild(h('div', { class: 'grid cols-4', style: 'margin-top:8px' },\n            stat('Aircraft', f.plane || 'unknown', MAP_KIND_NAMES[mapKind(f.plane)]),\n            stat('Took off', f.takeoffAt ? hm(f.takeoffAt) : 'unknown', f.takeoffAt ? ago(f.takeoffAt) : 'seen already in flight'),\n            stat('Lands (estimate)', f.landingAt ? (f.landingAt > nowS ? '~' + hm(f.landingAt) : 'about to land') : '—', f.landingAt > nowS ? 'in ' + durTxt(f.landingAt - nowS) : ''),\n            stat('Last action', f.lastAction ? ago(f.lastAction) : '—')));\n          if (prog !== null) infoBox.appendChild(h('div', { class: 'rprog', role: 'progressbar', 'aria-valuenow': String(prog), 'aria-valuemin': '0', 'aria-valuemax': '100' }, h('div', { style: 'width:' + prog + '%' })));\n          return;\n        }\n        const list = d.flying.filter(f => f.country === sel.k).sort((a, b) => (a.landingAt || 9e12) - (b.landingAt || 9e12));\n        const out = list.filter(f => f.direction !== 'return').length;\n        const recent = (d.recent || []).filter(f => f.country === sel.k).slice(0, 5);\n        infoBox.appendChild(h('h3', { text: sel.k + ' · ' + out + ' going out, ' + (list.length - out) + ' coming back' }));\n        if (!list.length) infoBox.appendChild(h('p', { class: 'muted small', text: 'Nobody is flying there right now.' }));\n        else infoBox.appendChild(h('div', { class: 'tablewrap' }, h('table', null,\n          h('thead', null, h('tr', null, ['Player', 'Direction', 'Aircraft', 'Took off', 'Lands (estimate)'].map(x => h('th', { text: x })))),\n          h('tbody', null, list.map(f => h('tr', { class: 'clk', onclick: () => { RADAR_SEL = { t: 'p', k: f.id }; drawMap(); } },\n            h('td', null, h('b', { text: f.name || '#' + f.id })), h('td', { text: f.direction === 'return' ? '← back' : '→ out' }), h('td', { text: f.plane || '?' }),\n            h('td', { class: 'muted', text: f.takeoffAt ? hm(f.takeoffAt) : 'unknown' }),\n            h('td', { text: f.landingAt ? (f.landingAt > nowS ? '~' + hm(f.landingAt) + ' (in ' + durTxt(f.landingAt - nowS) + ')' : 'about to land') : '—' })))))));\n        if (recent.length) infoBox.appendChild(h('p', { class: 'muted small', style: 'margin-top:8px', text: 'Latest recorded flights here: ' + recent.map(f => (f.name || '#' + f.id) + ' ' + hm(f.takeoffAt)).join(' · ') }));\n      }\n      const legend = h('div', { class: 'rmap-legend small muted' },\n        ['airliner', 'light', 'jet', 'biz'].map(k => h('span', { class: 'lg' }, svgIcon(k), ' ' + MAP_KIND_NAMES[k])),\n        h('span', { class: 'lg out' }, 'blue = going out'), h('span', { class: 'lg back' }, 'gold = coming back'), h('span', { class: 'lg' }, '● take-off unknown'), h('span', { class: 'lg hot' }, '◎ hot spot: 3+ landing within 3 min'));\n      P.map.appendChild(h('div', { class: 'card rmapcard' }, mapHost, legend));\n      P.map.appendChild(h('div', { class: 'card', style: 'margin-top:12px' }, infoBox));\n      drawMap();\n      if (!infoTimer) infoTimer = setInterval(() => { if (!infoBox.isConnected) { clearInterval(infoTimer); infoTimer = null; return; } if (RADAR_SEL && RADAR_SEL.t === 'p') drawInfo(); }, 1000);\n      P.dest.appendChild(dataTable({ persistKey: 'radar-dest', rows: d.countries, defaultSort: 'count', defaultDir: 'desc', empty: empty('Nobody is flying', 'Employees in flight will appear here.'), cols: [\n        { key: 'country', label: 'Destination', render: c => h('b', { text: c.country }) },\n        { key: 'direction', label: 'Direction', render: c => h('span', { class: 'badge ' + (c.direction === 'return' ? '' : 'info'), text: c.direction === 'return' ? 'Back to Torn' : 'Going out' }) },\n        { key: 'count', label: 'Flying' },\n        { key: 'firstLanding', label: 'Estimated landings', sortVal: c => c.firstLanding || 9e12, render: c => h('span', { class: 'muted', text: c.withLanding ? (c.firstLanding === c.lastLanding ? '~' + hm(c.firstLanding) : '~' + hm(c.firstLanding) + ' to ~' + hm(c.lastLanding)) + ' (' + c.withLanding + ' known)' : 'unknown yet' }) }\n      ] }).el);\n      P.flying.appendChild(dataTable({ persistKey: 'radar-flying', rows: d.flying, defaultSort: 'landingAt', defaultDir: 'asc', empty: empty('Nobody is flying'), cols: [\n        { key: 'name', label: 'Player', sortVal: f => (f.name || '').toLowerCase(), render: f => h('span', {}, h('b', { text: f.name || '#' + f.id }), h('span', { class: 'muted small', text: ' ' + (f.position || '') })) },\n        { key: 'company', label: 'Company', render: f => h('span', { class: 'muted', text: f.company || '' }) },\n        { key: 'country', label: 'Where', render: f => h('span', { text: place(f.country, f.direction) }) },\n        { key: 'plane', label: 'Aircraft', render: f => h('span', { text: f.plane || '?' }) },\n        { key: 'takeoffAt', label: 'Took off', sortVal: f => f.takeoffAt || 0, render: f => h('span', { class: 'muted', text: f.takeoffAt ? hm(f.takeoffAt) : 'before we looked' }) },\n        { key: 'landingAt', label: 'Lands (estimate)', sortVal: f => f.landingAt || 9e12, render: f => h('span', { text: f.landingAt ? (f.landingAt > now ? '~' + hm(f.landingAt) + ' (in ' + durTxt(f.landingAt - now) + ')' : 'about to land') : '—' }) }\n      ] }).el);\n      P.history.appendChild(dataTable({ persistKey: 'radar-recent', rows: d.recent, defaultSort: 'takeoffAt', defaultDir: 'desc', empty: empty('No flight recorded yet', 'A flight is recorded when we see a player on the ground and then in the air.'), cols: [\n        { key: 'name', label: 'Player', sortVal: f => (f.name || '').toLowerCase(), render: f => h('b', { text: f.name || '#' + f.id }) },\n        { key: 'company', label: 'Company', render: f => h('span', { class: 'muted', text: f.company || '' }) },\n        { key: 'country', label: 'Where', render: f => h('span', { text: place(f.country, f.direction) }) },\n        { key: 'plane', label: 'Aircraft', render: f => h('span', { text: f.plane || '?' }) },\n        { key: 'takeoffAt', label: 'Take-off', sortVal: f => f.takeoffAt, render: f => h('span', { text: dFmt(f.takeoffAt) + ' (±' + Math.round(f.windowSec / 2) + ' s)' }) },\n        { key: 'landedSeenAt', label: 'Landing seen', sortVal: f => f.landedSeenAt || 0, render: f => h('span', { class: 'muted', text: f.landedSeenAt ? hm(f.landedSeenAt) + ' · flight ' + durTxt(f.landedSeenAt - f.takeoffAt) : '—' }) }\n      ] }).el);\n      // ---- Signals + Players (reliability score)\n      const scoreBadge = (v, conf) => h('span', { class: 'badge ' + (v >= 80 ? 'ok' : v >= 60 ? 'info' : v >= 40 ? '' : 'warn'), title: conf ? 'confidence: ' + conf : '', text: v + '%' });\n      const controls = (onChange) => h('div', { class: 'card rctl' },\n        h('label', { class: 'small' }, 'Minimum player score ', h('b', { class: 'rctl-v', text: RADAR_MIN_SCORE + '%' }),\n          h('input', { type: 'range', min: 0, max: 100, step: 5, value: String(RADAR_MIN_SCORE), 'aria-label': 'Minimum player score', oninput: (e) => { e.target.parentNode.querySelector('.rctl-v').textContent = e.target.value + '%'; }, onchange: (e) => { RADAR_MIN_SCORE = Number(e.target.value); saveRadarPrefs(); onChange(); } })),\n        h('label', { class: 'small' }, 'Players needed in a group ',\n          h('select', { 'aria-label': 'Players needed in a group', onchange: (e) => { RADAR_MIN_PLAYERS = Number(e.target.value); saveRadarPrefs(); onChange(); } }, [2, 3, 4, 5, 6, 8, 10].map(n => h('option', { value: String(n), selected: n === RADAR_MIN_PLAYERS, text: String(n) })))));\n      function drawSignals() {\n        clear(P.signals);\n        if (!I) { P.signals.appendChild(h('div', { class: 'card' }, empty('Signals unavailable', 'Try again in a moment.'))); return; }\n        const body = h('div');\n        P.signals.appendChild(controls(refreshAll));\n        P.signals.appendChild(body);\n        drawSignalList(body);\n      }\n      const money = (n) => n === null || n === undefined ? '—' : (n < 0 ? '-' : '') + '$' + Math.abs(n).toLocaleString('en-US');\n      // Items worth watching for a group: profitable items that are out of stock now, and anything restocked since take-off.\n      function watchLine(c) {\n        if (!ST || !ST.enabled) return null;\n        const co = ST.countries.find(x => x.name === c.country); if (!co) return null;\n        const empty = co.items.filter(i => i.qty === 0 && i.profit > 0).sort((a, b) => b.profit - a.profit).slice(0, 3);\n        const fresh = ST.events.filter(e => e.countryName === c.country && e.seenAt >= c.start - 120).slice(0, 3);\n        if (!empty.length && !fresh.length) return null;\n        return h('p', { class: 'small', style: 'margin:8px 0 0' },\n          fresh.length ? h('span', { class: 'badge ok', text: 'restocked since take-off: ' + fresh.map(e => e.name).join(', ') }) : null, fresh.length && empty.length ? ' ' : null,\n          empty.length ? h('span', { class: 'muted', text: 'empty and profitable now: ' + empty.map(i => i.name + ' (' + money(i.profit) + ')').join(', ') }) : null);\n      }\n      function drawSignalList(body) {\n        clear(body);\n        const list = sigList(), nowS = Math.floor(Date.now() / 1000) + (d.now - Math.floor(loadedAt / 1000));\n        body.appendChild(h('p', { class: 'muted small', style: 'margin:10px 2px', text: 'A signal = at least ' + RADAR_MIN_PLAYERS + ' players with a score of ' + RADAR_MIN_SCORE + '% or more taking off for the same country within 3 minutes. ' + I.usableFlights + ' flights analysed over ' + I.days + ' days.' }));\n        if (!list.length) { body.appendChild(h('div', { class: 'card' }, empty('No signal', 'Nothing matches these settings yet. Lower the score or the group size, or wait for more flights.'))); return; }\n        list.forEach(c => {\n          const landTxt = !c.landFirst ? 'landing unknown' : c.landLast > nowS ? 'lands ~' + hm(c.landFirst) + (c.landLast !== c.landFirst ? ' to ~' + hm(c.landLast) : '') + (c.landFirst > nowS ? ' (in ' + durTxt(c.landFirst - nowS) + ')' : ' (now)') : 'landed ' + ago(c.landLast);\n          body.appendChild(h('div', { class: 'card sig', style: 'margin-bottom:10px' },\n            h('div', { class: 'row', style: 'justify-content:space-between;align-items:center' },\n              h('div', null, h('b', { text: '→ ' + c.country }), h('span', { class: 'muted small', text: '  took off ' + hm(c.start) + (c.end > c.start ? '–' + hm(c.end) : '') + ' · ' + ago(c.start) })),\n              h('div', { class: 'row' }, h('span', { class: 'badge info', text: c.good.length + ' players' }), scoreBadge(c.avg), h('span', { class: 'badge ' + (c.landLast > nowS ? 'acc' : ''), text: landTxt }))),\n            watchLine(c),\n            h('div', { class: 'chips', style: 'margin-top:8px' }, c.members.map(m => h('span', { class: 'chip' + (m.score >= RADAR_MIN_SCORE ? '' : ' dim'), text: (m.name || '#' + m.id) + ' ' + m.score + '%' })))));\n        });\n      }\n      let playerBody = h('div');\n      function drawPlayerTable() {\n        clear(playerBody);\n        if (!I) return;\n        const rows = I.players.filter(p => p.score >= RADAR_MIN_SCORE);\n        playerBody.appendChild(h('p', { class: 'muted small', style: 'margin:10px 2px', text: rows.length + ' of ' + I.players.length + ' players at ' + RADAR_MIN_SCORE + '% or more. Score = share of a player\\'s flights that left together with at least 2 others; a new player starts at about 50%.' }));\n        playerBody.appendChild(dataTable({ persistKey: 'radar-players', rows, defaultSort: 'score', defaultDir: 'desc', empty: empty('No player yet', 'Players appear after their first recorded flight.'), cols: [\n          { key: 'name', label: 'Player', sortVal: p => (p.name || '').toLowerCase(), render: p => h('span', null, h('b', { text: p.name || '#' + p.id }), h('span', { class: 'muted small', text: ' ' + (p.position || '') })) },\n          { key: 'company', label: 'Company', render: p => h('span', { class: 'muted', text: p.company || '' }) },\n          { key: 'score', label: 'Score', render: p => scoreBadge(p.score, p.confidence) },\n          { key: 'inGroups', label: 'In a group', sortVal: p => p.inGroups, render: p => h('span', { text: p.inGroups + ' / ' + p.usable }) },\n          { key: 'flights', label: 'Flights' },\n          { key: 'perDay', label: 'Per day' },\n          { key: 'confidence', label: 'Confidence', sortVal: p => ({ high: 3, medium: 2, low: 1 })[p.confidence] || 0, render: p => h('span', { class: 'muted', text: p.confidence }) },\n          { key: 'lastFlightAt', label: 'Last flight', sortVal: p => p.lastFlightAt || 0, render: p => h('span', { class: 'muted', text: p.lastFlightAt ? ago(p.lastFlightAt) : '—' }) }\n        ] }).el);\n      }\n      function drawPlayers() { clear(P.players); P.players.appendChild(controls(refreshAll)); P.players.appendChild(playerBody); drawPlayerTable(); }\n      function refreshAll() { drawSignals(); drawPlayers(); const t = bar.children[1]; if (t) t.textContent = 'Signals (' + sigList().length + ')'; }\n      drawSignals(); drawPlayers();\n      // ---- Stock tab: filters on the left, items / planner on the right\n      const detCache = new Map();\n      const cad = (m) => !m ? '—' : m >= 120 ? '~' + Math.round(m / 60) + ' h' : '~' + m + ' min';\n      const clock = (sec) => { const d = new Date(sec * 1000), u = RADAR_PLAN.tz === 'utc'; return pad(u ? d.getUTCHours() : d.getHours()) + ':' + pad(u ? d.getUTCMinutes() : d.getMinutes()) + ':' + pad(u ? d.getUTCSeconds() : d.getSeconds()); };\n      const clockHM = (sec) => clock(sec).slice(0, 5);\n      const dayHM = (sec) => { const d = new Date(sec * 1000), u = RADAR_PLAN.tz === 'utc'; return pad(u ? d.getUTCDate() : d.getDate()) + '/' + pad((u ? d.getUTCMonth() : d.getMonth()) + 1) + ' ' + pad(u ? d.getUTCHours() : d.getHours()) + 'h'; };\n      const stNow = () => Math.floor(Date.now() / 1000) + (ST ? ST.now - Math.floor(loadedAt / 1000) : 0);\n      const aircraftName = () => (PLAN_TYPES.find(t => t[0] === RADAR_PLAN.type) || [0, 0, ''])[2];\n      const types = ST ? Array.from(new Set(ST.countries.flatMap(c => c.items.map(i => i.type || 'Other')))).sort() : [];\n      const inTxt = (sec, now) => sec > now ? ' (in ' + fmtDur(sec - now) + ')' : '';\n      const redrawStock = () => setTimeout(drawStock, 0);\n\n      function planSide() {\n        const P = RADAR_PLAN, set = () => { savePlan(); redrawStock(); };\n        const chip = (label, on, fn) => h('button', { class: 'pchip' + (on ? ' on' : ''), type: 'button', 'aria-pressed': String(on), onclick: fn }, label);\n        const allNames = PLAN_GROUPS.flatMap(g => g[1]);\n        const cOn = (n) => !P.countries || P.countries.indexOf(n) >= 0;\n        const toggleC = (n) => { const cur = P.countries ? P.countries.slice() : allNames.slice(); const i = cur.indexOf(n); if (i >= 0) cur.splice(i, 1); else cur.push(n); P.countries = cur.length === allNames.length ? null : cur; set(); };\n        const groupSet = (names, on) => { const cur = P.countries ? P.countries.slice() : allNames.slice(); names.forEach(n => { const i = cur.indexOf(n); if (on && i < 0) cur.push(n); if (!on && i >= 0) cur.splice(i, 1); }); P.countries = cur.length === allNames.length ? null : cur; set(); };\n        const tOn = (t) => !P.types || P.types.indexOf(t) >= 0;\n        const toggleT = (t) => { const cur = P.types ? P.types.slice() : types.slice(); const i = cur.indexOf(t); if (i >= 0) cur.splice(i, 1); else cur.push(t); P.types = cur.length === types.length ? null : cur; set(); };\n        const num = (label, key, help, ph) => h('label', { class: 'small pnum' }, h('span', { class: 'muted', text: label }), h('input', { type: 'text', inputmode: 'numeric', placeholder: ph || '', value: P[key] ? String(P[key]) : '', 'aria-label': label, title: help || '', onchange: (e) => { P[key] = Math.max(0, Math.floor(Number(String(e.target.value).replace(/[^0-9]/g, '')) || 0)); set(); } }));\n        return h('aside', { class: 'card tside' },\n          h('div', { class: 'tside-head' }, h('b', { class: 'small muted', text: 'TRIP & FILTERS' }), h('button', { class: 'plink', type: 'button', onclick: () => { const keep = { view: P.view, tz: P.tz, range: P.range }; RADAR_PLAN = Object.assign({}, PLAN_DEFAULT, keep); savePlan(); redrawStock(); } }, 'Reset')),\n          h('div', { class: 'small muted', text: 'Trip' }),\n          h('div', { class: 'pseg', role: 'radiogroup', 'aria-label': 'Aircraft' }, PLAN_TYPES.map(t => h('button', { type: 'button', role: 'radio', 'aria-checked': String(P.type === t[0]), title: t[2], class: P.type === t[0] ? 'on' : '', onclick: () => { P.type = t[0]; set(); } }, t[1]))),\n          h('div', { class: 'tgrid2' }, num('Carry', 'carry', 'Items you can bring back per flight'), num('Cash', 'cash', 'Your cash in $ (empty = no limit)', 'Unlimited'), num('Sell at % of market', 'sell', 'TornW3B uses 95'), num('Land after restock (s)', 'buffer', 'Safety margin: land this many seconds after the predicted restock')),\n          h('div', { class: 'small muted sec', text: 'Countries' }),\n          PLAN_GROUPS.map(g => h('div', { class: 'pgroup' }, h('span', { class: 'small muted', text: g[0] }), h('button', { class: 'plink', type: 'button', onclick: () => groupSet(g[1], true) }, 'all'), h('button', { class: 'plink', type: 'button', onclick: () => groupSet(g[1], false) }, 'none'),\n            h('div', { class: 'pchips' }, g[1].map(n => chip(n, cOn(n), () => toggleC(n)))))),\n          types.length ? h('div', { class: 'pgroup' }, h('span', { class: 'small muted sec', text: 'Item types' }), h('button', { class: 'plink', type: 'button', onclick: () => { P.types = null; set(); } }, 'all'), h('button', { class: 'plink', type: 'button', onclick: () => { P.types = []; set(); } }, 'none'),\n            h('div', { class: 'pchips' }, types.map(t => chip(t, tOn(t), () => toggleT(t))))) : null,\n          h('div', { class: 'sec' }, h('label', { class: 'small' }, h('input', { type: 'checkbox', checked: P.profitOnly, onchange: (e) => { P.profitOnly = e.target.checked; set(); } }), ' Profitable only'),\n            h('label', { class: 'small' }, h('input', { type: 'checkbox', checked: P.stockedOnly, onchange: (e) => { P.stockedOnly = e.target.checked; set(); } }), ' In stock only')));\n      }\n      function stockGate(host) {\n        if (!ST) { host.appendChild(h('div', { class: 'card' }, empty('Stock unavailable', 'Try again in a moment.'))); return false; }\n        if (!ST.enabled) { host.appendChild(h('div', { class: 'card' }, empty('Stock feed is off', 'The foreign stock is not connected yet.'))); return false; }\n        if (!ST.countries.length) { host.appendChild(h('div', { class: 'card' }, empty('Waiting for the first stock', 'The first snapshot arrives within a minute.'))); return false; }\n        return true;\n      }\n      function takeoffCell(r) {\n        const now = stNow();\n        if (r.avail === 'now') return h('span', null, h('b', { class: 'ok-text', text: 'Now' }), h('span', { class: 'muted small', text: r.qtyLand > 0 && r.rate > 0 ? ' ~' + r.qtyLand.toLocaleString('en-US') + ' left on landing' : '' }));\n        if (r.avail === 'restock') return h('span', null, h('b', { text: clock(r.departAt) }), h('span', { class: 'muted small', text: r.departAt > now ? inTxt(r.departAt, now) : ' leave now' }));\n        if (r.avail === 'late') return h('span', { class: 'bad-text', text: 'Sold out by arrival' });\n        return h('span', { class: 'muted', text: r.qty > 0 ? 'no forecast yet' : 'no forecast yet' });\n      }\n      function itemDetail(r) {\n        const box = h('div', { class: 'idet' });\n        const P0 = RADAR_PLAN;\n        function paint() {\n          clear(box); const now = stNow();\n          box.appendChild(h('div', { class: 'pseg rng', role: 'tablist' }, [['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days']].map(x => h('button', { type: 'button', role: 'tab', 'aria-selected': String(P0.range === x[0]), class: P0.range === x[0] ? 'on' : '', onclick: () => { P0.range = x[0]; savePlan(); paint(); } }, x[1]))));\n          const kpi = (k, v, hint, cls) => h('div', { class: 'kpi ' + (cls || '') }, h('div', { class: 'k', text: k }), h('div', { class: 'v', text: v }), hint ? h('div', { class: 'small muted', text: hint }) : null);\n          box.appendChild(h('div', { class: 'kpis' },\n            kpi('Depletion rate', r.depletionNow > 0 ? r.depletionNow.toLocaleString('en-US') + '/min' : r.depletionMed > 0 ? r.depletionMed.toLocaleString('en-US') + '/min' : '—', r.depletionMed > 0 ? 'Median: ' + r.depletionMed.toLocaleString('en-US') + '/min' : 'not enough data yet'),\n            kpi('Restock delay', cad(r.cadenceMin), r.restocks + ' restock' + (r.restocks === 1 ? '' : 's') + ' seen'),\n            kpi('Restock qty', r.restockQty > 0 ? compact(r.restockQty) : '—', r.cycles + ' cycle' + (r.cycles === 1 ? '' : 's')),\n            kpi('Sell out time', r.sellOutSec > 0 ? fmtDur(r.sellOutSec) : '—', r.soldOuts + ' sell-out' + (r.soldOuts === 1 ? '' : 's') + ' measured'),\n            kpi('Empties at', r.emptiesAt > 0 ? clockHM(r.emptiesAt) : '—', r.emptiesAt > now ? 'in ' + fmtDur(r.emptiesAt - now) : r.qty === 0 ? 'already empty' : '', r.emptiesAt > 0 ? 'hl' : ''),\n            kpi('Price', r.market > 0 ? compact(r.market, true) : '—', 'market value · shop ' + money(r.cost))));\n          let cls = 'muted', head, line;\n          if (r.avail === 'now') { cls = 'ok'; head = 'Stock should still be there'; line = r.rate > 0 ? 'About ' + r.qtyLand.toLocaleString('en-US') + ' left when you land.' : 'The stock is not moving: you can leave now.'; }\n          else if (r.avail === 'restock') { cls = 'warn'; head = 'Wait for the restock'; line = 'Take off at ' + clock(r.departAt) + ' to land ' + P0.buffer + ' s after the restock at ' + clock(r.nextRestockAt) + (r.qty > 0 ? ' (the current stock will be gone by then).' : '.'); }\n          else if (r.avail === 'late') { cls = 'bad'; head = 'Likely sold out by arrival time'; line = 'Already too late to land before this stock empties, and no restock is forecast yet.'; }\n          else { head = 'No forecast yet'; line = 'This item has not restocked while we were watching.'; }\n          box.appendChild(h('div', { class: 'lbox ' + cls }, h('div', { class: 'small', text: 'On landing' }), h('b', { text: head }), h('div', { text: line }), h('div', { class: 'small muted', text: fmtDur(r.dur) + ' one-way · ' + aircraftName() + ' · plan for ' + (r.units || 0) + ' item' + (r.units === 1 ? '' : 's') })));\n          const stockCard = h('div', { class: 'card cwrap' }, h('div', { class: 'small muted ctitle', text: 'STOCK LEVEL — HISTORY & FORECAST' }), h('div', { class: 'small muted', text: 'Loading…' }));\n          const priceCard = h('div', { class: 'card cwrap' }, h('div', { class: 'small muted ctitle', text: 'PRICE MOVEMENT — LAST ' + P0.range.replace('h', ' HOURS').replace('d', ' DAYS') }));\n          box.appendChild(stockCard); box.appendChild(priceCard);\n          const key = r.key + '|' + P0.range, hit = detCache.get(key);\n          if (!hit || Date.now() - hit.t > 60000) detCache.set(key, { t: Date.now(), p: api('GET', '/api/radar/stock/item?country=' + encodeURIComponent(r.code) + '&id=' + r.id + '&range=' + P0.range) });\n          detCache.get(key).p.then(res => {\n            if (!box.isConnected) return;\n            clear(stockCard); stockCard.appendChild(h('div', { class: 'small muted ctitle', text: 'STOCK LEVEL — HISTORY & FORECAST' }));\n            if (!res.ok || !res.data || !res.data.ok) { stockCard.appendChild(h('div', { class: 'small muted', text: 'Could not load the history.' })); return; }\n            const d = res.data, long = P0.range !== '24h', nowT = d.now;\n            let fc = null, x1 = nowT; const landT = (r.avail === 'restock' ? r.departAt : nowT) + r.dur;\n            if (!long) {\n              fc = [[nowT, r.qty]];\n              if (r.qty > 0 && r.emptiesAt > nowT) fc.push([r.emptiesAt, 0]);\n              if (r.nextRestockAt > nowT && r.restockQty > 0) { if (fc[fc.length - 1][1] !== 0) fc.push([r.nextRestockAt, 0]); fc.push([r.nextRestockAt, r.restockQty]); if (r.sellOutSec > 0) fc.push([r.nextRestockAt + r.sellOutSec, 0]); }\n              x1 = Math.min(nowT + 8 * 3600, Math.max(nowT + 1800, fc[fc.length - 1][0], r.avail !== 'none' ? landT + 600 : 0));\n            }\n            const markers = d.restocks.map(e => ({ t: e[0], cls: 'mk-restock' })).concat(d.soldouts.map(t => ({ t, cls: 'mk-sold' })));\n            if (!long && r.avail !== 'none' && r.avail !== 'late') markers.push({ t: landT, cls: 'mk-land', text: 'You land ' + clockHM(landT) });\n            stockCard.appendChild(lineChart({ points: d.points, x0: d.since, x1, nowT, step: true, cls: 'stock', markers, forecast: fc, yFmt: (v) => compact(v), xFmt: (t) => long ? dayHM(t) : clockHM(t), label: 'Stock level of ' + r.name, tip: (t, v) => clock(t) + ' · ' + v.toLocaleString('en-US') + ' in stock' }));\n            stockCard.appendChild(h('div', { class: 'legend small muted' }, h('span', { class: 'lg g', text: 'Restock' }), h('span', { class: 'lg r', text: 'Sold out' }), long ? null : h('span', { class: 'lg o', text: 'You land' }), long ? null : h('span', { class: 'lg p', text: 'Predicted next cycle' })));\n            clear(priceCard); priceCard.appendChild(h('div', { class: 'small muted ctitle', text: 'PRICE MOVEMENT — LAST ' + P0.range.replace('h', ' HOURS').replace('d', ' DAYS') }));\n            if (d.prices.length < 2) priceCard.appendChild(h('div', { class: 'small muted', text: 'Not enough price changes yet. The market value is read every 30 minutes.' }));\n            else priceCard.appendChild(lineChart({ points: d.prices, x0: d.since, x1: nowT, nowT, step: true, cls: 'price', autoMin: true, h: 170, yFmt: (v) => compact(v, true), xFmt: (t) => long ? dayHM(t) : clockHM(t), label: 'Price of ' + r.name, tip: (t, v) => clock(t) + ' · ' + money(Math.round(v)) }));\n          });\n        }\n        paint();\n        // the detail sits in a table cell: keep it as wide as the visible table, not as the (possibly wider) scrolling table\n        const fit = () => { const w = box.closest ? box.closest('.tablewrap') : null; if (w) { box.style.width = Math.max(260, w.clientWidth - 2) + 'px'; box.style.position = 'sticky'; box.style.left = '0'; } };\n        requestAnimationFrame(fit); window.addEventListener('resize', fit);\n        return box;\n      }\n      function filtered() {\n        const P = RADAR_PLAN; let rows = planRows(ST, P, stNow());\n        if (P.profitOnly) rows = rows.filter(r => r.pu > 0);\n        if (P.stockedOnly) rows = rows.filter(r => r.qty > 0);\n        return rows;\n      }\n      function drawStock() {\n        clear(P.stock);\n        if (!stockGate(P.stock)) return;\n        const PL = RADAR_PLAN, now = stNow(), rows = filtered();\n        const lay = h('div', { class: 'tlayout' }), main = h('div', { class: 'tmain' });\n        lay.appendChild(planSide()); lay.appendChild(main); P.stock.appendChild(lay);\n        const seg = (opts, cur, fn, label) => h('div', { class: 'pseg', role: 'radiogroup', 'aria-label': label }, opts.map(o => h('button', { type: 'button', role: 'radio', 'aria-checked': String(cur === o[0]), class: cur === o[0] ? 'on' : '', onclick: () => fn(o[0]) }, o[1])));\n        main.appendChild(h('div', { class: 'card ttool' },\n          h('span', { class: 'small muted', text: rows.length + ' deals · ' + aircraftName() }),\n          h('div', { class: 'row', style: 'gap:10px;flex-wrap:wrap' },\n            seg([['items', 'Items'], ['planner', 'Planner']], PL.view, (v) => { PL.view = v; savePlan(); redrawStock(); }, 'View'),\n            h('span', { class: 'small muted', text: 'Times' }), seg([['utc', 'TCT'], ['local', 'Local']], PL.tz, (v) => { PL.tz = v; savePlan(); redrawStock(); }, 'Times'),\n            h('input', { type: 'search', placeholder: 'Search items…', value: PL.q || '', 'aria-label': 'Search an item', onchange: (e) => { PL.q = e.target.value; savePlan(); redrawStock(); } }))));\n        // best routes: the best item of each country, three best countries\n        const bestBy = {};\n        rows.forEach(r => { if (r.perHour > 0 && (!bestBy[r.country] || r.perHour > bestBy[r.country].perHour)) bestBy[r.country] = r; });\n        const top = Object.keys(bestBy).map(k => bestBy[k]).sort((a, b) => b.perHour - a.perHour).slice(0, 3);\n        main.appendChild(h('div', { class: 'small muted rhead' }, h('b', { text: 'Best routes' }), top.length ? h('span', { text: 'Tap to filter the list' }) : null));\n        main.appendChild(top.length ? h('div', { class: 'rcards' }, top.map((r, i) => h('button', { type: 'button', class: 'rcard' + (i === 0 ? ' best' : ''), onclick: () => { PL.countries = [r.country]; savePlan(); redrawStock(); } },\n          h('div', { class: 'small' }, h('b', { text: r.country }), h('span', { class: 'muted', text: i === 0 ? '  BEST' : '  #' + (i + 1) })),\n          h('div', { class: 'rbig ok-text', text: money(r.perHour) + '/hr' }), h('div', { class: 'small muted', text: r.name + (r.avail === 'restock' ? ' · after restock' : '') })))) : h('div', { class: 'card' }, empty('No route', 'Nothing profitable is available with these filters.')));\n        if (PL.view === 'planner') return drawPlannerView(main, rows, now);\n        main.appendChild(dataTable({ persistKey: 'radar-stock', rows, defaultSort: 'perHour', defaultDir: 'desc', pageSize: 30, rowKey: r => r.key, expand: itemDetail, empty: empty('Nothing matches', 'Change the filters on the left.'), cols: [\n          { key: 'country', label: 'Country', render: i => h('span', { text: flag(i.country) + i.country }) },\n          { key: 'name', label: 'Item', render: i => h('span', null, h('b', { text: i.name }), h('span', { class: 'muted small', text: ' ' + (i.type || '') })) },\n          { key: 'qty', label: 'Stock', render: i => h('span', { class: i.qty === 0 ? 'bad-text' : '', text: i.qty.toLocaleString('en-US') }) },\n          { key: 'pu', label: 'Profit', sortVal: i => i.pu === null ? -9e15 : i.pu, render: i => h('span', { class: i.pu > 0 ? 'ok-text' : 'muted', text: i.pu === null ? '—' : (i.pu > 0 ? '+' : '') + money(i.pu) }) },\n          { key: 'perHour', label: '$/hr', render: i => h('span', { class: i.perHour > 0 ? 'ok-text' : 'muted', text: i.perHour > 0 ? '+' + money(i.perHour) : '—' }) },\n          { key: 'nextRestockAt', label: 'Next restock', sortVal: i => i.nextRestockAt > 0 ? i.nextRestockAt : 9e12, render: i => i.nextRestockAt > 0 ? h('span', null, h('b', { text: clock(i.nextRestockAt) }), h('span', { class: 'muted small', text: i.nextRestockAt > now ? inTxt(i.nextRestockAt, now) : ' (due)' }), h('span', { class: 'badge ' + (i.nextConfidence >= 0.6 ? 'ok' : ''), style: 'margin-left:6px', title: 'confidence of the forecast', text: Math.round(i.nextConfidence * 100) + '%' })) : h('span', { class: 'muted', text: i.restocks ? 'learning…' : 'not seen yet' }) },\n          { key: 'departAt', label: 'Take off at', sortVal: i => i.avail === 'now' ? now : i.avail === 'restock' ? i.departAt : 9e12, render: takeoffCell },\n          { key: 'emptiesAt', label: 'Empties at', sortVal: i => i.emptiesAt > 0 ? i.emptiesAt : 9e12, render: i => i.emptiesAt > 0 ? h('span', null, h('b', { text: clockHM(i.emptiesAt) }), h('span', { class: 'muted small', text: inTxt(i.emptiesAt, now) })) : h('span', { class: 'muted', text: i.qty === 0 ? 'empty' : '—' }) },\n          { key: 'cadenceMin', label: 'Cycle', render: i => h('span', { class: 'muted', text: cad(i.cadenceMin) }) }\n        ].filter(c => c.key !== 'cadenceMin') }).el);\n        main.appendChild(h('p', { class: 'muted small', style: 'margin:10px 2px', text: 'Take off at = predicted restock + ' + PL.buffer + ' s − flight time. Sell-out and restock times are measured from the stock we record every few seconds; they get better with time. Click a row for the charts.' }));\n        main.appendChild(h('h3', { style: 'margin-top:20px', text: 'Latest restocks' }));\n        main.appendChild(dataTable({ persistKey: 'radar-restocks', rows: ST.events, defaultSort: 'seenAt', defaultDir: 'desc', pageSize: 15, empty: empty('No restock seen yet', 'A restock is recorded when an item\\'s quantity goes up between two updates.'), cols: [\n          { key: 'seenAt', label: 'Seen', render: e => h('span', { text: clockHM(e.seenAt) + ' (±' + Math.round((e.seenAt - e.prevAt) / 2) + ' s)' }) },\n          { key: 'countryName', label: 'Country' },\n          { key: 'name', label: 'Item', render: e => h('b', { text: e.name }) },\n          { key: 'after', label: 'Quantity', sortVal: e => e.after, render: e => h('span', { text: e.before.toLocaleString('en-US') + ' → ' + e.after.toLocaleString('en-US') }) },\n          { key: 'cost', label: 'Cost', render: e => h('span', { text: money(e.cost) }) }\n        ] }).el);\n      }\n      function drawPlannerView(main, rows, now) {\n        const PL = RADAR_PLAN;\n        const hz = h('select', { 'aria-label': 'Plan length', onchange: (e) => { PL.horizon = Number(e.target.value); savePlan(); redrawStock(); } }, [4, 8, 12, 24].map(n => h('option', { value: String(n), selected: n === PL.horizon, text: n + ' hours' })));\n        main.appendChild(h('h3', { style: 'margin-top:16px', text: 'Day plan' }));\n        main.appendChild(h('div', { class: 'row small', style: 'margin-bottom:8px' }, 'Plan for ', hz, h('span', { class: 'muted', text: ' trips are chosen one after another: the best profit per hour, waiting included.' })));\n        const plan = dayPlan(rows, PL, now);\n        if (!plan.trips.length) { main.appendChild(h('div', { class: 'card' }, empty('No trip fits', 'Try a longer plan, a faster aircraft or fewer filters.'))); return; }\n        main.appendChild(h('div', { class: 'tablewrap' }, h('table', null,\n          h('thead', null, h('tr', null, ['#', 'Take off', 'Where', 'Buy', 'Land', 'Back', 'Profit'].map(x => h('th', { text: x })))),\n          h('tbody', null, plan.trips.map((t, i) => h('tr', null,\n            h('td', { text: String(i + 1) }), h('td', null, h('b', { text: clock(t.depart) }), h('span', { class: 'muted small', text: t.depart > now + 30 ? inTxt(t.depart, now) : ' now' })),\n            h('td', { text: '→ ' + t.r.country }), h('td', null, h('b', { text: t.r.name }), h('span', { class: 'muted small', text: ' × ' + t.r.units + (t.r.avail === 'restock' ? ' · after restock ' + clock(t.r.nextRestockAt) : '') })),\n            h('td', { text: clock(t.land) }), h('td', { text: clock(t.back) }), h('td', { class: 'ok-text', text: money(t.r.units * t.r.pu) })))))));\n        main.appendChild(h('p', { class: 'small', style: 'margin:8px 2px' }, 'Total over ' + PL.horizon + ' h: ', h('b', { class: 'ok-text', text: money(plan.total) }), h('span', { class: 'muted', text: ' · estimate: stock that is selling fast may be gone when you land.' })));\n      }\n      drawStock();\n      show();\n      box.appendChild(h('div', { class: 'note info', style: 'margin-top:16px' }, 'Torn does not give landing times for other players. The take-off is the middle of the gap between two reads, the aircraft comes from Torn, and the landing is calculated. A booked flight can land earlier than shown. “Before we looked” means the player was already flying when we first saw them.'));\n      if (window.scrollY !== keepY) window.scrollTo(0, keepY);\n    }\n    await load();\n    timer = setInterval(() => { if (route().page !== 'radar') { clearInterval(timer); return; } if (!typing()) load(); }, 30000);\n  }\n\n  async function warPage() {\n    view.appendChild(head('War', 'Watch the members of an enemy faction: who is flying, which aircraft, when they land.'));\n    const top = h('div', {}), list = h('div', { style: 'margin-top:16px' });\n    view.appendChild(top); view.appendChild(list);\n    let data = null, onlyAway = true, timer = null;\n\n    async function load() {\n      const r = await api('GET', '/api/war');\n      if (!r.ok) { clear(top).appendChild(h('div', { class: 'card' }, empty('War mode unavailable'))); return; }\n      data = r.data; keepScroll(view, () => { drawTop(); drawList(); });\n    }\n    function drawTop() {\n      clear(top);\n      const cfg = data.config || {};\n      const fid = h('input', { type: 'text', inputmode: 'numeric', placeholder: 'Enemy faction ID', value: cfg.factionId ? String(cfg.factionId) : '', style: 'width:160px', class: 'mono' });\n      const msg = h('p', { class: 'muted small', role: 'status' });\n      const save = async (extra) => {\n        const id = fid.value.trim() === '' ? 0 : Number(fid.value.trim());\n        const r = await api('PUT', '/api/war', Object.assign({ factionId: id }, extra || {}));\n        if (r.ok) { data = r.data; drawTop(); drawList(); toast('War settings saved.'); } else msg.textContent = (r.data && r.data.message) || 'Could not save.';\n      };\n      top.appendChild(h('div', { class: 'card' },\n        h('h2', { text: 'Enemy faction' }),\n        h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;align-items:center' }, fid,\n          h('button', { onclick: () => save() }, 'Save'),\n          h('button', { class: 'ghost', onclick: async () => {\n            msg.textContent = 'Looking for your faction\\'s war…';\n            const r = await api('POST', '/api/war/detect');\n            if (r.ok && r.data.enemy) { fid.value = r.data.enemy.id; msg.textContent = 'Found: ' + (r.data.enemy.name || ('faction ' + r.data.enemy.id)) + ' (' + r.data.enemy.kind + ' war). Press Save to use it.'; }\n            else msg.textContent = (r.data && r.data.message) || 'No war found.';\n          } }, 'Find my enemy')),\n        h('div', { class: 'switch', style: 'margin-top:12px' }, h('span', { class: 'muted', text: 'Server tracking (Premium)' }),\n          h('button', { class: cfg.enabled ? '' : 'ghost', onclick: () => save({ enabled: !cfg.enabled }) }, cfg.enabled ? 'On' : 'Off')),\n        data.premium ? null : h('div', { class: 'note' }, 'The server only follows the enemy faction for Premium members. Without Premium, the overlay still watches the war while Torn is open (War tab in the overlay).'),\n        data.state ? h('p', { class: 'muted small', text: (data.state.factionName || 'Faction') + ' · ' + data.state.memberCount + ' members · ' + (data.state.lastOkAt ? 'updated ' + ago(data.state.lastOkAt) : 'not collected yet') + (data.state.lastError ? ' · last error: ' + data.state.lastError : '') }) : null,\n        msg));\n    }\n    function drawList() {\n      clear(list);\n      const now = Math.floor(Date.now() / 1000);\n      let rows = (data.members || []).slice();\n      if (!data.config.factionId) { list.appendChild(h('div', { class: 'card' }, empty('No enemy faction yet', 'Enter its ID above, or press \"Find my enemy\".'))); return; }\n      if (!data.premium) { return; }\n      if (!rows.length) { list.appendChild(h('div', { class: 'card' }, empty('No data yet', 'Turn server tracking on: the first roster arrives within a minute.'))); return; }\n      const away = rows.filter(m => m.state !== 'Okay');\n      list.appendChild(h('div', { class: 'row', style: 'justify-content:space-between;margin-bottom:8px' },\n        h('span', { class: 'muted small', text: rows.length + ' members · ' + rows.filter(m => m.state === 'Traveling').length + ' flying · ' + rows.filter(m => m.state === 'Abroad').length + ' abroad · ' + rows.filter(m => m.state === 'Hospital').length + ' in hospital' }),\n        h('label', { class: 'small' }, h('input', { type: 'checkbox', checked: onlyAway, onchange: (e) => { onlyAway = e.target.checked; drawList(); } }), ' Only members away from Torn')));\n      if (onlyAway) rows = away;\n      const eta = (m) => m.state === 'Traveling' ? (m.takeoffAt > 0 && m.duration > 0 ? m.takeoffAt + m.duration : 9e12) : (m.until || 9e12);\n      rows.sort((a, b) => (WAR_RANK[a.state] ?? 9) - (WAR_RANK[b.state] ?? 9) || eta(a) - eta(b));\n      const body = rows.map(m => {\n        const fly = m.state === 'Traveling';\n        const where = fly ? (m.direction === 'return' ? '← ' : '→ ') + (m.country || m.description) : m.state === 'Abroad' ? 'In ' + (m.country || m.description.replace(/^In /i, '')) : m.state === 'Hospital' ? 'back at ' + (m.until ? hhmmSec(m.until) : '?') : (m.description || '—');\n        const land = fly && m.takeoffAt > 0 && m.duration > 0 ? m.takeoffAt + m.duration : 0;\n        const lands = fly ? (land > now ? '~' + hhmmSec(land) + ' (in ' + durTxt(land - now) + ')' : land ? 'about to land' : 'unknown (seen mid-flight)') : m.state === 'Hospital' && m.until > now ? 'in ' + durTxt(m.until - now) : '—';\n        return h('tr', null,\n          h('td', null, h('b', { text: m.name || ('#' + m.id) }), h('span', { class: 'muted small', text: ' [' + m.id + ']' })),\n          h('td', { text: String(m.level || '') }), h('td', null, h('span', { class: 'badge ' + (fly ? 'info' : m.state === 'Hospital' ? 'bad' : m.state === 'Abroad' ? 'acc' : 'ok'), text: m.state || '—' })),\n          h('td', { text: where }), h('td', { text: fly ? (m.plane || 'unknown') : '—' }), h('td', { text: lands }),\n          h('td', { class: 'muted', text: m.lastAction ? ago(m.lastAction) : '—' }));\n      });\n      list.appendChild(h('div', { class: 'tablewrap' }, h('table', null,\n        h('thead', null, h('tr', null, ['Member', 'Lvl', 'Status', 'Where', 'Aircraft', 'Lands / back', 'Last action'].map(x => h('th', { text: x })))),\n        h('tbody', null, body.length ? body : h('tr', null, h('td', { colspan: 7, class: 'muted', text: 'Nobody is away from Torn right now.' }))))));\n    }\n    await load();\n    timer = setInterval(() => { if (route().page !== 'war') { clearInterval(timer); return; } if (!typing()) load(); }, 30000);\n  }\n\n  /* ================= PAGE: premium ================= */\n  async function premiumPage() {\n    view.appendChild(head('Premium', 'Always-on tracking by the server, even when your browser is closed.'));\n    const box = h('div', { style: 'display:grid;gap:16px;grid-template-columns:minmax(0,1fr);max-width:980px' }); view.appendChild(box);\n    box.appendChild(h('div', { class: 'skeleton', style: 'height:140px' }));\n    const r = await api('GET', '/api/premium');\n    clear(box);\n    if (!r.ok || !r.data.premium) { box.appendChild(h('div', { class: 'card' }, empty('Premium status unavailable'))); return; }\n    const pr = r.data.premium, pay = r.data.payment || {}, hist = r.data.history || [];\n    S.pay = pay; if (S.me) { S.me.premium = pr; updateChip(); }\n    const kwEl = (t) => h('span', { class: 'kw', text: t || pay.keyword });\n    const perXan = pay.daysPerXanax || 7;\n\n    // --- status\n    const hero = h('div', { class: 'card hero ' + (pr.active ? 'on' : '') });\n    hero.appendChild(svgEl(pr.active ? LOGO_CROWN : LOGO, 'big-logo'));\n    const info = h('div');\n    if (pr.admin) {\n      info.appendChild(h('span', { class: 'badge acc', text: 'Administrator' }));\n      info.appendChild(h('h2', { style: 'margin-top:8px', text: 'Premium is always active on your account.' }));\n    } else if (pr.active) {\n      info.appendChild(h('span', { class: 'badge ok', text: 'Premium active' }));\n      const cd = h('div', { class: 'countdown', style: 'margin-top:6px', text: leftText(pr.until) + ' left' });\n      info.appendChild(cd);\n      info.appendChild(h('p', { class: 'muted', style: 'margin-top:4px' }, 'Ends on ', h('b', { text: dFull(pr.until) }), ' (your local time).'));\n      const iv = setInterval(() => { if (!document.body.contains(cd)) { clearInterval(iv); return; } cd.textContent = leftText(pr.until) + ' left'; updateChip(); }, 20000);\n      info.appendChild(h('a', { class: 'btn-gold', style: 'margin-top:10px', href: '#get' , onclick: (e) => { e.preventDefault(); $('#getPremium').scrollIntoView({ behavior: 'smooth' }); } }, 'Add more days'));\n    } else {\n      info.appendChild(h('span', { class: 'badge', text: pr.until ? 'Premium expired' : 'Not Premium' }));\n      info.appendChild(h('h2', { style: 'margin-top:8px', text: pr.until ? 'Your Premium ended on ' + dFull(pr.until) + '.' : 'Get always-on tracking.' }));\n      info.appendChild(h('p', { class: 'muted', text: 'Data the server already collected for you stays saved and comes back as soon as Premium is active.' }));\n      info.appendChild(h('a', { class: 'btn-gold', style: 'margin-top:6px', href: '#get', onclick: (e) => { e.preventDefault(); $('#getPremium').scrollIntoView({ behavior: 'smooth' }); } }, 'Go Premium'));\n    }\n    hero.appendChild(info); box.appendChild(hero);\n\n    // --- what you get\n    box.appendChild(h('div', { class: 'feat' },\n      h('div', { class: 'card' }, h('h3', { text: 'Always-on tracking' }), h('p', { class: 'muted small', text: 'The server checks your players about once a minute, day and night, with no browser or script open.' })),\n      h('div', { class: 'card' }, h('h3', { text: 'A solid history' }), h('p', { class: 'muted small', text: 'Departures, arrivals and status changes are saved and shown in History and Statistics, with the exact observation window.' })),\n      h('div', { class: 'card' }, h('h3', { text: 'Simple and fair' }), h('p', { class: 'muted small', text: perXan + ' days per Xanax. No subscription, no automatic renewal: you extend when you want.' }))));\n\n    if (pay.bonus) box.appendChild(h('div', { class: 'note', style: 'border-left-color:var(--gold)' }, h('b', { text: '\\u265b ' + (pay.bonus === 'company' ? 'Company' : pay.bonus === 'both' ? 'Faction and company' : 'Faction') + ' bonus. ' }), 'You are in the same ' + (pay.bonus === 'both' ? 'faction and company' : pay.bonus) + ' as the developer: each Xanax gives you ' + perXan + ' days instead of 7.'));\n\n    // --- how to get / extend\n    const profile = pay.profileUrl ? h('a', { href: pay.profileUrl, target: '_blank', rel: 'noopener noreferrer' }, (pay.payeeName || 'the owner') + ' [' + pay.payeeId + ']') : h('b', { text: (pay.payeeName || '') + ' [' + (pay.payeeId || '') + ']' });\n    const how = h('div', { class: 'card', id: 'getPremium' },\n      h('h2', { text: pr.active ? 'Add more days' : 'How to go Premium' }),\n      h('ol', { class: 'steps' },\n        h('li', null, h('b', { text: 'Send a Xanax in Torn. ' }), 'Open your inventory, click a Xanax, then ', h('b', { text: 'Send' }), '. Send it to ', profile, '.'),\n        h('li', null, h('b', { text: 'Write the message ' }), kwEl(), '. Capital letters and spaces do not matter (Scope, SCOPE, “ scope ”, “scope please” all work).'),\n        h('li', null, h('b', { text: 'Choose the amount. ' }), 'Each Xanax adds ', h('b', { text: perXan + ' days' }), '. You can send several at once (up to ' + (pay.maxXanax || 52) + ', about one year). Days add up on top of what you have left.'),\n        h('li', null, h('b', { text: 'That is it. ' }), 'Your Premium is credited automatically within a few minutes. The Xanax must come from your Torn account ', h('b', { class: 'mono', text: '[' + (pay.yourTornId || (S.me && S.me.tornUserId) || '') + ']' }), ', the one linked to this TornScope account.')),\n      h('img', { class: 'shot', src: SHOT_SEND, alt: 'Torn send-item form: message “scope”, user ID of the owner, amount 1', width: 704, height: 138, loading: 'lazy' }),\n      h('p', { class: 'muted small', style: 'margin-top:6px', text: 'This is the Torn form: type the message in the first field, the owner’s ID in “User ID”, and the amount.' }),\n      pay.profileUrl ? h('p', { style: 'margin-top:12px' }, h('a', { class: 'btn-gold', href: pay.profileUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Open ' + (pay.payeeName || 'the owner') + '’s profile on Torn')) : null,\n      h('p', { class: 'muted small', style: 'margin-top:12px' }, 'Not credited after 10 minutes? Check that the message contains ', kwEl(), ' and that it was sent from the linked account. If it still does not appear, message ' + (pay.payeeName || 'the owner') + ' in Torn with the date and the amount.'));\n    box.appendChild(how);\n\n    // --- history\n    if (hist.length) {\n      box.appendChild(h('h3', { style: 'margin-top:6px', text: 'Your Premium history' }));\n      box.appendChild(dataTable({ rows: hist, defaultSort: 'createdAt', defaultDir: 'desc', pageSize: 10, empty: empty('Nothing yet'), cols: [\n        { key: 'createdAt', label: 'Date', render: c => h('span', { text: dFmt(c.createdAt) }) },\n        { key: 'hours', label: 'Added', sortVal: c => c.hours, render: c => h('b', { text: c.hours > 0 ? '+' + daysOf(c.hours) : '—' }) },\n        { key: 'source', label: 'Source', render: c => h('span', { class: 'badge', text: c.source === 'xanax' ? 'Xanax' : (c.source === 'manual' ? 'Manual' : (c.source === 'revoke' ? 'Removed' : c.source)) }) }] }).el);\n    }\n\n    // --- optional API key\n    box.appendChild(keyCard());\n  }\n\n  /* ================= PAGE: settings ================= */\n  function settings() {\n    view.appendChild(head('Settings', 'Account, theme, overlay token and security. Premium and your API key are on the Premium page.'));\n    const theme = S.prefs.theme || 'dark';\n    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Theme' }, [['system', 'System'], ['dark', 'Dark'], ['light', 'Light']].map(([v, l]) =>\n      h('button', { class: theme === v ? 'on' : '', type: 'button', onclick: () => { setTheme(v); clear(view); settings(); } }, l)));\n    view.appendChild(h('div', { class: 'grid cols-2' },\n      h('div', { class: 'card' }, h('h2', { text: 'Account' }),\n        h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Username' }), h('b', { text: S.me ? S.me.username : '—' })),\n        h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Linked Torn ID' }), h('b', { class: 'mono', text: S.me ? String(S.me.tornUserId) : '—' })),\n        h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Role' }), h('b', { text: S.me && S.me.role === 'admin' ? 'Administrator' : 'Player' })),\n        h('p', { class: 'muted small', text: 'Your Torn API key stays in your script, on your device, unless you choose to add it on the Premium page.' })),\n      h('div', { class: 'card' }, h('h2', { text: 'Appearance' }), h('p', { class: 'muted small', text: 'Dark and Light are fixed. System follows your device or browser setting (not the time of day). Your choice is remembered on this browser and on your account.' }), seg)));\n\n    const out = h('input', { type: 'text', readonly: true, autocomplete: 'off', placeholder: 'Your token appears here, once', class: 'mono', style: 'width:100%' });\n    const tmsg = h('p', { class: 'muted small', role: 'status' });\n    view.appendChild(h('div', { class: 'card', style: 'margin-top:16px' }, h('h2', { text: 'Overlay token' }),\n      h('p', { class: 'muted small', text: 'This token links your Tampermonkey / Torn PDA script to this account. It is only shown when created: copy it, then paste it into the script settings. Never share it.' }),\n      h('div', { class: 'row' },\n        h('button', { onclick: async () => {\n          if (!confirm('Generate a new token? Older ones stay valid until you revoke them.')) return;\n          tmsg.textContent = 'Generating…'; const r = await api('POST', '/overlay/token');\n          if (r.ok && r.data.token) { out.value = r.data.token; out.select(); tmsg.textContent = 'Token created. Copy it now.'; } else tmsg.textContent = r.data.message || 'Failed.';\n        } }, 'Generate a token'),\n        h('button', { class: 'ghost', onclick: async () => { if (!out.value) { tmsg.textContent = 'Nothing to copy.'; return; } try { await navigator.clipboard.writeText(out.value); tmsg.textContent = 'Copied.'; } catch (e) { out.select(); tmsg.textContent = 'Selected: copy it manually.'; } } }, 'Copy'),\n        h('button', { class: 'danger', onclick: async () => { if (!confirm('Revoke ALL tokens? Your script will have to be reconnected.')) return; const r = await api('POST', '/overlay/token/revoke'); out.value = ''; tmsg.textContent = r.data.message || (r.ok ? 'Revoked.' : 'Failed.'); } }, 'Revoke all')),\n      h('div', { style: 'margin-top:10px' }, out), tmsg));\n\n    const pm = h('p', { class: 'muted small', role: 'status' });\n    const cur = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Current password', required: true, maxlength: 128 });\n    const n1 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'New password (12 characters minimum)', required: true, minlength: 12, maxlength: 128 });\n    const n2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Confirm the new password', required: true, maxlength: 128 });\n    view.appendChild(h('div', { class: 'grid cols-2', style: 'margin-top:16px' },\n      (S.me && S.me.keyLogin) ? h('div', { class: 'card' }, h('h2', { text: 'Sign-in' }), h('p', { class: 'muted small', text: 'You log in with your Torn API key: there is no password to manage. To log in on another device, paste a Public key again.' })) : h('div', { class: 'card' }, h('h2', { text: 'Change password' }),\n        h('form', { class: 'stack', onsubmit: async (ev) => {\n          ev.preventDefault(); if (n1.value !== n2.value) { pm.textContent = 'The two passwords do not match.'; return; }\n          pm.textContent = 'Saving…'; const r = await api('POST', '/account/password', { currentPassword: cur.value, newPassword: n1.value });\n          pm.textContent = r.data.message || (r.ok ? 'Changed.' : 'Failed.'); if (r.ok) ev.target.reset();\n        } }, cur, n1, n2, h('button', { type: 'submit' }, 'Change password')), pm),\n      h('div', { class: 'card' }, h('h2', { text: 'Sessions' }), h('p', { class: 'muted small', text: 'Log out all your other devices (phone, other PC…). This device stays logged in.' }),\n        h('button', { class: 'ghost', onclick: async () => { const r = await api('POST', '/account/sessions/revoke-others'); toast(r.data.message || (r.ok ? 'Done.' : 'Failed.')); } }, 'Close my other sessions'))));\n  }\n\n\n\n  const kw = () => (S.pay && S.pay.keyword) || 'TTW';\n  async function loadPay() {\n    if (S.pay) return S.pay;\n    const r = await api('GET', '/api/premium');\n    S.pay = (r.ok && r.data.payment) || { keyword: 'TTW', payeeId: '', payeeName: '', hoursPerXanax: 168, profileUrl: '' };\n    return S.pay;\n  }\n\n  const TERMS_ROWS = [[\"Data stored\", \"In the script: your API key, targets and alerts stay on your device. On our server, only if you link a TornScope account: your account (username, Torn ID, and a password hash only for password accounts), the list of players you watch, the status changes seen for them (state, destination, take-off and landing times), for War mode only: the ID of the enemy faction you chose; your Premium credits and a yes/no flag “same faction / same company as the owner”.\"], [\"Data shared\", \"Nothing is sold, published or given to third parties. Each member sees only their own targets and history.\"], [\"Purpose of use\", \"Show alerts and history for the players you choose. Premium: the server does the tracking while your browser is closed. War mode (optional): the public member list of the enemy faction you choose is read from Torn (status, travel, last action) to show who is travelling; for Premium the server keeps this public snapshot and the aircraft deduced, shared by members watching the same faction. Public profiles are also read to give members of the owner's faction or company a longer Premium.\"], [\"Key storage and sharing\", \"Login: the key you paste to log in is sent once to Torn to check who you are, then discarded; it is not stored. Script: your key stays in your browser or Torn PDA and is sent only to api.torn.com, never to our server. Optional key saved on the site: stored encrypted (AES-256-GCM), never displayed, logged or sent back to your browser, never shared, deletable any time. It may be used to check players watched by other Premium members, only for their public status.\"], [\"Key access level\", \"Public access is enough; nothing higher is requested. (Only the owner's own Full key is used, to read the owner's own log and spot Xanax payments; message text is compared with a keyword and not stored.)\"]];\n  function termsTable() {\n    return h('div', null,\n      h('table', { class: 'tt' }, ...TERMS_ROWS.map(r => h('tr', null, h('th', { text: r[0] }), h('td', { text: r[1] })))),\n      h('p', { class: 'muted small' }, 'Full text: ', h('a', { href: '/terms', target: '_blank', rel: 'noopener noreferrer' }, 'How your data and API key are used')));\n  }\n\n  /* ================= Settings card: personal Torn API key (server-side collection) ================= */\n  function keyCard() {\n    const box = h('div', { class: 'card', style: 'margin-top:16px' });\n    const input = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'Paste your 16-character Public API key', maxlength: 40, class: 'mono', style: 'width:100%' });\n    const msg = h('p', { class: 'muted small', role: 'status' });\n\n    async function load() {\n      const r = await api('GET', '/api/key');\n      clear(box);\n      box.appendChild(h('h2', { text: 'Your Torn API key (optional)' }));\n      box.appendChild(h('p', { class: 'muted small', text: 'Lets the server use your own key to check players for you. For now the key is only stored safely: nothing uses it yet, and Premium works without it.' }));\n      const d = r.data || {};\n      if (r.ok && d.available === false) box.appendChild(h('div', { class: 'note' }, 'Key storage is not configured on the server yet (administrator: add the KEY_ENCRYPTION_SECRET secret).'));\n      const k = d.key;\n      if (k) {\n        box.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Status' }), h('span', { class: 'badge ' + (k.status === 'valid' ? 'ok' : 'bad'), text: k.status === 'valid' ? 'Valid' : k.status })));\n        box.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Owner' }), h('b', { text: (k.tornName || '—') + ' [' + k.tornId + ']' })));\n        box.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Access level' }), h('b', { text: k.accessType || 'unknown' })));\n        box.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Last verified' }), h('b', { text: k.lastOkAt ? ago(k.lastOkAt) : '—' })));\n        box.appendChild(h('p', { class: 'muted small', text: 'For security the key is never shown again. To change it, paste a new one below.' }));\n      }\n      box.appendChild(termsTable());\n      if (!(d.available === false)) {\n        box.appendChild(h('form', { class: 'stack', onsubmit: async (ev) => {\n          ev.preventDefault();\n          const v = input.value.trim(); input.value = '';\n          if (!v) { msg.textContent = 'Paste your key first.'; return; }\n          msg.textContent = 'Checking with Torn…';\n          const res = await api('PUT', '/api/key', { key: v });\n          if (res.ok) { await load(); msg.textContent = (res.data.message || 'Saved.') + (res.data.warning ? ' ' + res.data.warning : ''); }\n          else msg.textContent = res.data.message || 'Could not save the key.';\n        } }, input, h('div', { class: 'row' },\n          h('button', { type: 'submit' }, k ? 'Replace key' : 'Verify and save key'),\n          k ? h('button', { type: 'button', class: 'danger', onclick: async () => {\n            if (!confirm('Delete your key from the server?')) return;\n            const res = await api('DELETE', '/api/key'); await load(); toast(res.data.message || (res.ok ? 'Deleted.' : 'Failed.'));\n          } }, 'Delete my key') : null)));\n        box.appendChild(msg);\n      }\n    }\n    load();\n    return box;\n  }\n\n  /* ================= PAGE: admin ================= */\n  async function admin() {\n    if (!(S.me && S.me.role === 'admin')) { view.appendChild(h('div', { class: 'card' }, empty('Access denied', 'This page is reserved for administrators.'))); return; }\n    view.appendChild(head('Admin', 'Users, invitations, account recovery and service status.'));\n    const body = h('div'); view.appendChild(body);\n    body.appendChild(h('div', { class: 'skeleton', style: 'height:80px' }));\n    const [us, stt] = await Promise.all([api('GET', '/admin/users'), api('GET', '/admin/status')]);\n    clear(body);\n    const s = stt.data.status || {};\n    body.appendChild(h('div', { class: 'grid cols-4' },\n      stat('Accounts', String(s.accounts ?? '—'), (s.activeAccounts ?? '—') + ' active'), stat('Targets (total)', String(s.targets ?? '—')),\n      stat('Events', String(s.events ?? '—'), s.lastEventAt ? 'last: ' + ago(s.lastEventAt) : 'none'), stat('Active overlay tokens', String(s.activeOverlayTokens ?? '—'), (s.sessions ?? '—') + ' open sessions')));\n    const codeOut = h('input', { type: 'text', readonly: true, class: 'mono', style: 'width:100%', placeholder: 'The invitation or reset link appears here' });\n    const cmsg = h('p', { class: 'muted small', role: 'status' });\n    const uname = h('input', { type: 'text', placeholder: 'Username', maxlength: 32, required: true, autocomplete: 'off' });\n    body.appendChild(h('div', { class: 'grid cols-2', style: 'margin-top:16px' },\n      h('div', { class: 'card' }, h('h2', { text: 'Invite a player' }), h('p', { class: 'muted small', text: 'Generates a ready-to-send sign-up link (valid 7 days, single use).' }),\n        h('button', { onclick: async () => { cmsg.textContent = '…'; const r = await api('POST', '/admin/invitations'); if (r.ok) { codeOut.value = location.origin + '/join#code=' + r.data.invitationCode; codeOut.select(); cmsg.textContent = 'Invitation link created (valid 7 days, single use). Copy it now and send it to the player: it will not be shown again.'; } else cmsg.textContent = r.data.message || 'Failed.'; } }, 'Create an invitation link')),\n      h('div', { class: 'card' }, h('h2', { text: 'Forgotten password' }), h('p', { class: 'muted small', text: 'Generates a single-use link (1 h) so a player can choose a new password.' }),\n        h('form', { class: 'row', onsubmit: async (ev) => { ev.preventDefault(); cmsg.textContent = '…'; const r = await api('POST', '/admin/reset-codes', { username: uname.value.trim() });\n          if (r.ok) { codeOut.value = location.origin + '/reset#code=' + r.data.resetCode; cmsg.textContent = 'Link for ' + r.data.username + ' (1 h, single use).'; } else cmsg.textContent = r.data.message || 'Failed.'; } }, uname, h('button', { type: 'submit' }, 'Generate')))));\n    body.appendChild(h('div', { class: 'card', style: 'margin-top:16px' }, h('div', { class: 'row' }, h('div', { style: 'flex:1;min-width:0' }, codeOut), h('button', { class: 'ghost', type: 'button', onclick: async () => { if (!codeOut.value) { cmsg.textContent = 'Nothing to copy yet.'; return; } try { await navigator.clipboard.writeText(codeOut.value); cmsg.textContent = 'Link copied.'; } catch (e) { codeOut.select(); cmsg.textContent = 'Select the text and copy it manually.'; } } }, 'Copy')), cmsg));\n    body.appendChild(h('h3', { style: 'margin-top:22px', text: 'Users' }));\n    const users = (us.data.users || []);\n    body.appendChild(dataTable({ rows: users, defaultSort: 'username', defaultDir: 'asc', empty: empty('No users'), cols: [\n      { key: 'username', label: 'Name', sortVal: u => u.username.toLowerCase(), render: u => h('b', { text: u.username }) },\n      { key: 'tornUserId', label: 'Torn ID', render: u => h('span', { class: 'mono', text: String(u.tornUserId || '—') }) },\n      { key: 'role', label: 'Role', render: u => h('span', { class: 'badge ' + (u.role === 'admin' ? 'acc' : ''), text: u.role === 'admin' ? 'Admin' : 'Player' }) },\n      { key: 'active', label: 'Status', render: u => h('span', { class: 'badge ' + (u.active ? 'ok' : 'bad'), text: u.active ? 'Active' : 'Disabled' }) },\n      { key: 'targets', label: 'Targets' }, { key: 'events', label: 'Events' },\n      { key: 'tokens', label: 'Overlay tokens' },\n      { key: 'beta', label: 'Beta', sortVal: u => u.role === 'admin' ? 2 : (u.beta ? 1 : 0), render: u => u.role === 'admin' ? h('span', { class: 'badge acc', text: 'Always' }) : h('button', { class: u.beta ? '' : 'ghost', onclick: async (ev) => { const b = ev.currentTarget; b.disabled = true; const r = await api('POST', '/admin/beta', { accountId: u.id, enabled: !u.beta }); b.disabled = false; if (r.ok) { u.beta = r.data.enabled ? 1 : 0; b.textContent = u.beta ? 'On' : 'Off'; b.className = u.beta ? '' : 'ghost'; toast(u.username + (u.beta ? ' added to the beta' : ' removed from the beta')); } else toast(r.data.message || 'Failed'); } }, u.beta ? 'On' : 'Off') },\n      { key: 'keyStatus', label: 'API key', sortVal: u => u.keyStatus || '', render: u => h('span', { class: 'badge ' + (u.keyStatus === 'valid' ? 'ok' : (u.keyStatus ? 'bad' : '')), text: u.keyStatus === 'valid' ? 'Stored' : (u.keyStatus || 'None') }) }] }).el);\n    const premBox = h('div', { style: 'margin-top:22px' }); body.appendChild(premBox); premiumPanel(premBox);\n    const ownerBox = h('div', { style: 'margin-top:22px' }); body.appendChild(ownerBox); ownerKeyPanel(ownerBox);\n    const collectorBox = h('div', { style: 'margin-top:22px' }); body.appendChild(collectorBox); collectorPanel(collectorBox);\n    const usageBox = h('div', { style: 'margin-top:22px' }); body.appendChild(usageBox); apiUsagePanel(usageBox);\n    const radarBox = h('div', { style: 'margin-top:22px' }); body.appendChild(radarBox); radarPanel(radarBox);\n    const diagBox = h('div', { style: 'margin-top:22px' }); body.appendChild(diagBox); diagPanel(diagBox);\n    body.appendChild(h('div', { class: 'note info' }, 'Diagnostics: no sensitive data (password, token, API key) is ever shown here. Linking a Torn account by key verification and disabling accounts will come in a later step.'));\n  }\n\n\n  /* ================= Admin: requests made with the owner's API key ================= */\n  async function apiUsagePanel(box) {\n    const r = await api('GET', '/admin/api-usage');\n    clear(box);\n    box.appendChild(h('h3', { text: 'Requests made with your API key' }));\n    if (!r.ok) { box.appendChild(h('div', { class: 'note' }, 'Unavailable.')); return; }\n    const u = r.data.usage, cur = u.minutes[u.minutes.length - 1].n;\n    const pct = Math.round(100 * u.avg5 / u.limit);\n    const hhmm = (sec) => { const d = new Date(sec * 1000); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); };\n    box.appendChild(h('div', { class: 'grid cols-4' },\n      stat('This minute', String(cur), 'limit ' + u.limit + ' per minute'),\n      stat('Average, last 5 min', String(u.avg5), pct + '% of the limit'),\n      stat('Peak, last hour', String(u.peak), 'average ' + u.avg60 + ' per minute'),\n      stat('Last 24 hours', String(u.total24h))));\n    box.appendChild(h('div', { class: 'card' },\n      h('div', { class: 'chart-wrap' }, barChart(u.minutes.map(x => hhmm(x.m)), u.minutes.map(x => x.n), { label: 'Requests per minute with the owner key, last 60 minutes', maxLabels: 8 })),\n      h('p', { class: 'muted small', text: 'Only what TornScope sends with your key is counted (cron, radar, war, Xanax checks, diagnostics). Anything else you do with the same key (other scripts, other sites) is not included, so Torn may show a little more.' }),\n      h('button', { class: 'ghost', onclick: () => apiUsagePanel(box) }, 'Refresh')));\n    if (!box._t) box._t = setInterval(() => { if (!box.isConnected) { clearInterval(box._t); box._t = null; return; } apiUsagePanel(box); }, 30000);\n  }\n\n  /* ================= Admin: restock radar (beta) ================= */\n  async function radarPanel(box) {\n    const r = await api('GET', '/admin/radar');\n    clear(box);\n    box.appendChild(h('h3', { text: 'Restock radar (beta): Cruise Line companies' }));\n    if (!r.ok) { box.appendChild(h('div', { class: 'note' }, 'Radar data unavailable.')); return; }\n    const st = r.data.stats || {}, now = r.data.now, list = r.data.companies || [];\n    const ids = h('textarea', { rows: 3, placeholder: 'Company IDs, one per line or separated by commas', style: 'width:100%;font-family:var(--mono, monospace)' });\n    const msg = h('p', { class: 'muted small', role: 'status' });\n    box.appendChild(h('div', { class: 'card' },\n      h('p', { class: 'muted small', text: st.players + ' employees followed (' + st.flying + ' flying) · ' + st.flights + ' flights recorded (' + st.flights24h + ' in the last 24 h, ' + st.landed + ' with a landing seen). Each company costs 1 Torn request per read; busy ones are read about once a minute.' }),\n      ids,\n      h('div', { class: 'row', style: 'margin-top:8px' },\n        h('button', { onclick: async () => { msg.textContent = '…'; const res = await api('POST', '/admin/radar', { ids: ids.value }); if (res.ok) { toast(res.data.added + ' added, ' + res.data.existing + ' already there' + (res.data.invalid ? ', ' + res.data.invalid + ' ignored' : '')); radarPanel(box); } else msg.textContent = res.data.message || 'Failed.'; } }, 'Add companies'),\n        h('button', { class: 'ghost', onclick: async () => { msg.textContent = 'Reading…'; const res = await api('POST', '/admin/radar/run'); if (res.ok) { toast(res.data.result.companies + ' companies read'); radarPanel(box); } else msg.textContent = res.data.message || 'Failed.'; } }, 'Read now')),\n      msg));\n    box.appendChild(dataTable({ rows: list, defaultSort: 'id', defaultDir: 'asc', empty: empty('No companies yet', 'Paste company IDs above.'), cols: [\n      { key: 'id', label: 'Company', render: c => h('span', { class: 'mono', text: String(c.id) }) },\n      { key: 'name', label: 'Name', sortVal: c => (c.name || '').toLowerCase(), render: c => h('b', { text: c.name || '—' }) },\n      { key: 'rating', label: 'Rating', sortVal: c => c.rating || 0, render: c => h('span', { class: 'badge ' + (c.rating >= 7 ? 'ok' : ''), text: c.rating ? String(c.rating) : '—' }) },\n      { key: 'employees', label: 'Employees' },\n      { key: 'lastReadAt', label: 'Last read', sortVal: c => c.lastReadAt || 0, render: c => h('span', { class: 'muted', text: c.lastReadAt ? ago(c.lastReadAt) : 'never' }) },\n      { key: 'active', label: 'Status', sortVal: c => c.active ? (c.lastError ? 1 : 0) : 2, render: c => h('span', { class: 'badge ' + (!c.active ? 'bad' : c.lastError ? 'warn' : 'ok'), text: !c.active ? (c.lastError || 'Off') : c.lastError ? c.lastError : 'Active' }) },\n      { key: 'x', label: '', render: c => h('button', { class: 'ghost', onclick: async () => { if (!confirm('Remove company ' + c.id + ' and its employees from the radar?')) return; const res = await api('POST', '/admin/radar', { remove: c.id }); toast(res.ok ? 'Removed' : (res.data.message || 'Failed')); radarPanel(box); } }, 'Remove') }\n    ] }).el);\n  }\n\n  /* ================= Admin: Torn API diagnostic ================= */\n  function diagPanel(box) {\n    box.appendChild(h('h3', { text: 'Torn API diagnostic' }));\n    const kind = h('select', { 'aria-label': 'What to read' },\n      h('option', { value: 'company', text: 'Company (employees, status)' }), h('option', { value: 'profile', text: 'Player profile (job, status)' }),\n      h('option', { value: 'personalstats', text: 'Player personal stats' }), h('option', { value: 'faction', text: 'Faction (members, wars)' }),\n      h('option', { value: 'torncompanies', text: 'Company types (empty ID = list; type ID = details)' }));\n    const id = h('input', { type: 'text', placeholder: 'ID', inputmode: 'numeric', style: 'width:130px', autocomplete: 'off' });\n    const out = h('pre', { class: 'mono small', style: 'white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;margin:10px 0 0' });\n    const msg = h('p', { class: 'muted small', role: 'status' });\n    box.appendChild(h('div', { class: 'card' },\n      h('p', { class: 'muted small', text: 'Reads one thing from Torn with the owner key (1 request) and shows the shape of the answer. The key is never shown.' }),\n      h('form', { class: 'row', onsubmit: async (ev) => { ev.preventDefault(); msg.textContent = '…'; out.textContent = '';\n        const r = await api('GET', '/admin/diagnostic?kind=' + encodeURIComponent(kind.value) + '&id=' + encodeURIComponent(id.value.trim()));\n        msg.textContent = r.ok ? (r.data.tornError ? 'Torn refused: ' + JSON.stringify(r.data.tornError) : 'Done (HTTP ' + r.data.status + ')') : (r.data.message || 'Failed');\n        if (r.ok && r.data.shape) out.textContent = 'SHAPE\\n' + JSON.stringify(r.data.shape, null, 1) + '\\n\\nSAMPLE\\n' + r.data.sample; } },\n        kind, id, h('button', { type: 'submit' }, 'Read')), msg, out));\n  }\n\n  /* ================= Admin: premium credits ================= */\n  async function premiumPanel(box) {\n    await loadPay();\n    const r = await api('GET', '/admin/premium');\n    clear(box);\n    box.appendChild(h('h3', { text: 'Premium' }));\n    if (!r.ok) { box.appendChild(h('div', { class: 'note' }, 'Premium data unavailable.')); return; }\n    const msg = h('p', { class: 'muted small', role: 'status' });\n    const uname = h('input', { type: 'text', placeholder: 'Username', maxlength: 32, required: true, autocomplete: 'off' });\n    const hours = h('input', { type: 'number', min: 1, max: 365, value: 7, required: true, style: 'width:110px', 'aria-label': 'Days' });\n    const now = r.data.now;\n    box.appendChild(h('div', { class: 'card' },\n      h('p', { class: 'muted small', text: 'Credit days to a player (7 days = 1 Xanax, 14 days for players in your faction or company). Days add up on top of the remaining time. Server-side collection runs only for players watched by a Premium member (administrators always count).' }),\n      h('form', { class: 'row', onsubmit: async (ev) => { ev.preventDefault(); msg.textContent = '…';\n        const res = await api('POST', '/admin/premium', { username: uname.value.trim(), hours: Math.round(Number(hours.value) * 24) });\n        if (res.ok) { await premiumPanel(box); const m = $('#premMsg'); if (m) m.textContent = res.data.message; } else msg.textContent = res.data.message || 'Failed.'; } },\n        uname, hours, h('span', { class: 'muted', text: 'days' }), h('button', { type: 'submit' }, 'Credit days')), msg, h('p', { id: 'premMsg', class: 'muted small', role: 'status' })));\n    box.appendChild(dataTable({ rows: r.data.accounts || [], defaultSort: 'username', defaultDir: 'asc', empty: empty('No accounts'), cols: [\n      { key: 'username', label: 'Player', sortVal: u => u.username.toLowerCase(), render: u => h('b', { text: u.username }) },\n      { key: 'premiumUntil', label: 'Premium', sortVal: u => u.role === 'admin' ? 9e12 : (u.premiumUntil || 0), render: u => u.role === 'admin' ? h('span', { class: 'badge acc', text: 'Always (admin)' }) : (u.premiumUntil && u.premiumUntil > now ? h('span', { class: 'badge ok', text: 'Until ' + dFmt(u.premiumUntil) }) : h('span', { class: 'badge', text: u.premiumUntil ? 'Expired' : 'None' })) },\n      { key: 'id', label: '', render: u => (u.role !== 'admin' && u.premiumUntil && u.premiumUntil > now) ? h('button', { class: 'ghost', onclick: async () => { if (!confirm('Revoke premium for ' + u.username + '?')) return; const res = await api('POST', '/admin/premium', { username: u.username, revoke: true }); await premiumPanel(box); toast(res.data.message || 'Done.'); } }, 'Revoke') : '' }] }).el);\n    const pend = r.data.pending || [];\n    if (pend.length) {\n      box.appendChild(h('h3', { style: 'margin-top:16px', text: 'Xanax to review (' + pend.length + ')' }));\n      box.appendChild(h('p', { class: 'muted small', text: 'Xanax received with the message ‘' + kw() + '’ that could not be credited automatically (the sender has no account here, or the quantity is above the automatic limit). Type the player’s username, then credit, or dismiss.' }));\n      pend.forEach(p => {\n        const un = h('input', { type: 'text', placeholder: 'Username', maxlength: 32, autocomplete: 'off', style: 'width:150px' });\n        box.appendChild(h('div', { class: 'card', style: 'margin-bottom:8px' }, h('div', { class: 'row' },\n          h('span', { text: dFmt(p.entryTs) + ' · Torn ID ' + p.senderId + ' · ' + p.qty + ' Xanax · ' + p.reason }), un,\n          h('button', { onclick: async () => { const res = await api('POST', '/admin/premium', { pendingRef: p.ref, username: un.value.trim() }); await premiumPanel(box); toast(res.data.message || (res.ok ? 'Done.' : 'Failed.')); } }, 'Credit ' + daysOf(Math.min(8760, p.qty * 168))),\n          h('button', { class: 'ghost', onclick: async () => { if (!confirm('Dismiss this entry?')) return; const res = await api('POST', '/admin/premium', { pendingRef: p.ref, dismiss: true }); await premiumPanel(box); toast(res.data.message || 'Done.'); } }, 'Dismiss'))));\n      });\n    }\n    const cr = r.data.credits || [];\n    if (cr.length) box.appendChild(h('details', { style: 'margin-top:10px' }, h('summary', { text: 'Recent credits (' + cr.length + ')' }),\n      dataTable({ rows: cr, defaultSort: 'createdAt', defaultDir: 'desc', empty: empty('None'), cols: [\n        { key: 'createdAt', label: 'Date', render: c => h('span', { text: dFmt(c.createdAt) }) },\n        { key: 'username', label: 'Player' }, { key: 'hours', label: 'Added', render: c => h('span', { text: c.hours > 0 ? daysOf(c.hours) : '—' }) }, { key: 'source', label: 'Source' }, { key: 'note', label: 'Note' }] }).el));\n  }\n\n  /* ================= Admin: owner key (Full access) + log viewer ================= */\n  async function ownerKeyPanel(box) {\n    await loadPay();\n    const r = await api('GET', '/admin/owner-key');\n    clear(box);\n    box.appendChild(h('h3', { text: 'Owner key (Torn log access)' }));\n    const d = r.data || {};\n    const card = h('div', { class: 'card' }); box.appendChild(card);\n    card.appendChild(h('p', { class: 'muted small', text: 'Used only to read YOUR Torn log (to recognise Xanax sent with the message ‘' + kw() + '’ and credit Premium). Torn requires a Full Access key for the log. It is stored encrypted, never shown again, never logged. Delete it here, and revoke it in Torn, if you stop using this.' }));\n    if (r.ok && d.available === false) card.appendChild(h('div', { class: 'note' }, 'Key storage is not configured (add the KEY_ENCRYPTION_SECRET secret).'));\n    const k = d.key;\n    if (k) {\n      card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Status' }), h('span', { class: 'badge ' + (k.status === 'valid' ? 'ok' : 'bad'), text: k.status === 'valid' ? 'Valid' : k.status })));\n      card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Owner / access' }), h('b', { text: (k.tornName || '—') + ' [' + k.tornId + '] · ' + (k.accessType || 'unknown') })));\n      card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Last check' }), h('b', { text: k.lastCheckAt ? ago(k.lastCheckAt) : '—' })));\n      const dt = d.detector;\n      card.appendChild(h('h3', { style: 'margin-top:14px', text: 'Automatic Xanax detection' }));\n      card.appendChild(h('p', { class: 'muted small', text: 'Every ~2 minutes the server reads your log. A Xanax received with the message ‘' + kw() + '’ (any capitalisation or spacing) from a player who has an account here credits 7 days per Xanax (14 for players in your faction or company). Xanax without that message (yours) are ignored. Only entries newer than the first check are considered.' }));\n      if (!dt) card.appendChild(h('div', { class: 'note' }, 'No check yet: it starts with the next cron run (up to a few minutes).'));\n      else {\n        card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Last check' }), h('b', { text: dt.lastRunAt ? ago(dt.lastRunAt) : '—' })));\n        card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Last successful read' }), h('b', { text: dt.lastOkAt ? ago(dt.lastOkAt) : '—' })));\n        card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Watching entries since' }), h('b', { text: dFmt(dt.sinceTs) })));\n        card.appendChild(h('div', { class: 'switch' }, h('span', { class: 'muted', text: 'Credited / to review' }), h('b', { text: (dt.credited || 0) + ' / ' + (dt.pending || 0) })));\n        if (dt.lastError) card.appendChild(h('div', { class: 'note' }, 'Last error: ' + dt.lastError));\n      }\n    }\n    const input = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'Paste your Full Access key', maxlength: 40, class: 'mono', style: 'width:100%' });\n    const msg = h('p', { class: 'muted small', role: 'status' });\n    if (d.available !== false) card.appendChild(h('form', { class: 'stack', onsubmit: async (ev) => {\n      ev.preventDefault(); const v = input.value.trim(); input.value = ''; if (!v) { msg.textContent = 'Paste your key first.'; return; }\n      msg.textContent = 'Checking with Torn…'; const res = await api('PUT', '/admin/owner-key', { key: v });\n      if (res.ok) { await ownerKeyPanel(box); const m = $('#ownerMsg'); if (m) m.textContent = res.data.message; } else msg.textContent = res.data.message || 'Could not save the key.';\n    } }, input, h('div', { class: 'row' }, h('button', { type: 'submit' }, k ? 'Replace key' : 'Verify and save key'),\n      k ? h('button', { type: 'button', class: 'danger', onclick: async () => { if (!confirm('Delete the owner key from the server?')) return; const res = await api('DELETE', '/admin/owner-key'); await ownerKeyPanel(box); toast(res.data.message || 'Deleted.'); } }, 'Delete key') : null)));\n    card.appendChild(msg); card.appendChild(h('p', { id: 'ownerMsg', class: 'muted small', role: 'status' }));\n    if (k) {\n      const filter = h('input', { type: 'text', value: 'receive', maxlength: 40, style: 'width:160px', 'aria-label': 'Filter text' });\n      const out = h('pre', { class: 'mono small', style: 'white-space:pre-wrap;max-height:360px;overflow:auto;margin:8px 0 0', text: '' });\n      const lmsg = h('p', { class: 'muted small', role: 'status' });\n      card.appendChild(h('h3', { style: 'margin-top:16px', text: 'Log viewer (diagnostic)' }));\n      card.appendChild(h('p', { class: 'muted small', text: 'Shows the raw log entries of your own account that contain the filter text, to check what Torn returns (sender, item, quantity, message). Up to 15 entries, newest first. The default filter “receive” targets “Item receive” entries; if nothing matches, try “xanax” or leave it empty (every type). Torn may identify items by number rather than by name.' }));\n      card.appendChild(h('div', { class: 'row' }, filter,\n        h('button', { onclick: async () => {\n          lmsg.textContent = 'Reading the log…'; out.textContent = '';\n          const res = await api('GET', '/admin/owner-log?filter=' + encodeURIComponent(filter.value.trim()));\n          if (!res.ok) { lmsg.textContent = res.data.message || 'Failed.'; return; }\n          lmsg.textContent = res.data.fetched + ' entries read, ' + res.data.matched + ' match' + (res.data.matched > 15 ? ' (15 shown)' : '') + '.';\n          out.textContent = JSON.stringify(res.data.entries, null, 2);\n        } }, 'Read my log'),\n        h('button', { class: 'ghost', onclick: async () => { try { await navigator.clipboard.writeText(out.textContent); toast('Copied.'); } catch (e) { toast('Select the text and copy it manually.'); } } }, 'Copy')));\n      card.appendChild(lmsg); card.appendChild(out);\n    }\n  }\n\n  async function collectorPanel(box) {\n    const r = await api('GET', '/admin/collector');\n    clear(box);\n    if (!r.ok) { box.appendChild(h('div', { class: 'note' }, 'Collector status unavailable.')); return; }\n    const c = r.data, st = c.state, now = c.now;\n    const age = st.lastRunAt ? now - st.lastRunAt : null;\n    const paused = st.haltedUntil && st.haltedUntil > now;\n    let badge;\n    if (!c.keyConfigured) badge = ['bad', 'No Torn key'];\n    else if (age === null) badge = ['warn', 'Never ran'];\n    else if (paused) badge = ['warn', 'Paused'];\n    else if (age > 180) badge = ['bad', 'Not running'];\n    else badge = ['ok', 'Running'];\n    const manual = h('button', { class: 'ghost sm', onclick: async (ev) => { ev.target.disabled = true; ev.target.textContent = 'Running…'; const x = await api('POST', '/admin/collector/run'); toast(x.ok ? 'Run finished: ' + x.data.summary.polled + ' checked, ' + x.data.summary.events + ' event(s).' : (x.data.message || 'Run failed.')); await collectorPanel(box); } }, 'Run now');\n    box.appendChild(h('div', { class: 'head' }, h('div', {}, h('h2', { text: 'Automatic collector' }), h('p', { class: 'muted small', text: 'Checks every watched player on the Torn API once a minute, even when nobody is logged in and no script is open.' })), h('div', { class: 'row' }, h('span', { class: 'badge ' + badge[0], text: badge[1] }), manual)));\n    if (!c.keyConfigured) box.appendChild(h('div', { class: 'note' }, 'No Torn API key is configured on the server (secret TORN_API_KEY or COLLECTOR_API_KEY).'));\n    else if (age === null) box.appendChild(h('div', { class: 'note' }, 'The collector has never run. In Cloudflare: your Worker \\u2192 Settings \\u2192 Triggers \\u2192 Cron Triggers \\u2192 add the schedule * * * * * (every minute). A new trigger can take up to 15 minutes to start. You can press “Run now” to test immediately.'));\n    else if (age > 180 && !paused) box.appendChild(h('div', { class: 'note' }, 'The last run was ' + ago(st.lastRunAt).replace(' ago', '') + ' ago. The cron trigger is missing or stopped (check Settings \\u2192 Triggers \\u2192 Cron Triggers in Cloudflare).'));\n    if (paused) box.appendChild(h('div', { class: 'note' }, 'Paused until ' + dFmt(st.haltedUntil) + ' because Torn answered ' + (st.haltedReason || 'an error') + '. It resumes by itself.'));\n    box.appendChild(h('div', { class: 'grid cols-4' },\n      stat('Last run', age === null ? '—' : ago(st.lastRunAt), age === null ? '' : 'by ' + (st.lastRunTrigger === 'cron' ? 'the cron trigger' : 'a manual run')),\n      stat('Last observation', c.lastObservationAt ? ago(c.lastObservationAt) : '—', 'last time Torn was asked about a player'),\n      stat('Players watched', String(c.watchedTargets), c.subscriptions + ' subscriptions \\u00b7 ' + c.dueNow + ' due now \\u00b7 budget ' + c.budgetPerRun + '/run'),\n      stat('Events recorded', String(c.events.total), c.events.last24h + ' in the last 24 h')));\n    box.appendChild(h('div', { class: 'grid cols-4', style: 'margin-top:16px' },\n      stat('Runs', String(st.runsTotal)), stat('Torn requests', String(st.pollsTotal)), stat('Errors', String(st.errorsTotal), st.lastError ? 'last: ' + st.lastError + (st.lastErrorAt ? ' (' + ago(st.lastErrorAt) + ')' : '') : 'none'), stat('Last success', st.lastSuccessAt ? ago(st.lastSuccessAt) : '—')));\n    box.appendChild(h('h3', { style: 'margin-top:20px', text: 'Recent runs' }));\n    box.appendChild(dataTable({ rows: c.runs, pageSize: 10, defaultSort: 'startedAt', empty: empty('No run yet'), cols: [\n      { key: 'startedAt', label: 'Time', render: x => dFmt(x.startedAt) },\n      { key: 'trigger', label: 'Trigger', render: x => h('span', { class: 'badge ' + (x.trigger === 'cron' ? 'ok' : ''), text: x.trigger }) },\n      { key: 'polled', label: 'Checked', render: x => x.polled + ' / ' + x.due },\n      { key: 'errors', label: 'Errors', render: x => h('span', { class: x.errors ? 'badge bad' : 'muted', text: String(x.errors) }) },\n      { key: 'events', label: 'Events' }, { key: 'durationMs', label: 'Duration', render: x => x.durationMs + ' ms' },\n      { key: 'note', label: 'Note', sort: false, render: x => h('span', { class: 'muted small', text: x.note || '' }) }] }).el);\n    box.appendChild(h('h3', { style: 'margin-top:20px', text: 'Watched players' }));\n    box.appendChild(dataTable({ rows: c.targets, pageSize: 10, defaultSort: 'lastPolledAt', defaultDir: 'asc', empty: empty('No watched player'), cols: [\n      { key: 'name', label: 'Player', sortVal: x => (x.name || '').toLowerCase(), render: x => h('div', {}, h('b', { text: x.name || ('#' + x.tornId) }), h('div', { class: 'muted small mono', text: '#' + x.tornId })) },\n      { key: 'state', label: 'Status', render: x => stateBadge(x.state) },\n      { key: 'lastPolledAt', label: 'Last checked', sortVal: x => x.lastPolledAt || 0, render: x => x.lastPolledAt ? ago(x.lastPolledAt) : 'not yet' },\n      { key: 'nextPollAt', label: 'Next check', sortVal: x => x.nextPollAt || 0, render: x => x.nextPollAt <= now ? 'due' : 'in ' + dur(Math.max(1, Math.round((x.nextPollAt - now) / 60))) },\n      { key: 'polls', label: 'Checks' },\n      { key: 'errorCount', label: 'Errors', render: x => x.errorCount ? h('span', { class: 'badge bad', title: x.lastError || '', text: x.errorCount + ' \\u00b7 ' + (x.lastError || '') }) : h('span', { class: 'muted', text: '0' }) }] }).el);\n  }\n\n  /* ================= boot ================= */\n  $('#logout').addEventListener('click', async () => { await api('POST', '/logout'); location.replace('/app'); });\n  $('#refresh').addEventListener('click', async () => { await loadAll(false); go(true); toast('Data refreshed.'); });\n  $('#themeBtn').addEventListener('click', () => { const cur = document.documentElement.getAttribute('data-theme'); setTheme(cur === 'dark' ? 'light' : 'dark'); });\n  $('#burger').addEventListener('click', () => document.body.classList.toggle('menu'));\n  $('#scrim').addEventListener('click', () => document.body.classList.remove('menu'));\n  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.body.classList.remove('menu'); });\n  go();\n  loadAll(false).then(go);\n  const dataSig = () => JSON.stringify([S.targets, S.events && S.events.length, S.events && S.events[0], S.me && S.me.role]);\n  setInterval(() => {\n    if (document.hidden) return;\n    const before = dataSig();\n    loadAll(true).then(() => {\n      if (document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) return;\n      // Re-render only when something really changed (no flicker, no scroll jump otherwise).\n      if (dataSig() !== before && ['overview', 'targets'].indexOf(route().page) >= 0 && !route().arg) go(true);\n      updateBadge();\n    });\n  }, 60000);\n})();\n<\/script>\n<\/body>\n<\/html>\n";

// =====================================================================================
//  AUTONOMOUS COLLECTOR (Cron Trigger) — runs without any user, browser or userscript.
//
//  Rules:
//   * one Torn request per UNIQUE player, however many users watch him;
//   * we only record what Torn told us at a given moment (observed_at = our clock when the
//     answer arrived, observed_after = previous successful check => the true time is in between);
//   * landing / release times come from Torn (`status.until`) and are tagged "api";
//   * nothing is ever estimated or invented here;
//   * D1 is called a constant number of times per run (bulk statements over json_each), because the
//     Free plan allows 50 subrequests per invocation (fetches + D1 calls together).
// =====================================================================================
const COLLECT_DEFAULT_MAX_POLLS = 35;       // Free plan: 50 subrequests - ~13 D1 calls - margin
const COLLECT_HARD_MAX_POLLS = 90;          // Torn: 100 requests / minute / user, across all keys
const COLLECT_LEASE_SECONDS = 75;           // a claimed player is not claimed again by an overlapping run
const COLLECT_FETCH_TIMEOUT_MS = 8000;
const COLLECT_RUN_BUDGET_MS = 22000;
const COLLECT_CONCURRENCY = 6;              // Workers: 6 simultaneous outgoing connections
const COLLECT_KEY_HALT_SECONDS = 1800;      // invalid / disabled key: stop hammering Torn (IP-ban risk)
const COLLECT_RATE_HALT_SECONDS = 120;
const COLLECT_RUN_KEEP_SECONDS = 3 * 24 * 3600;
const POLL_ACTIVE = 60;                     // last action <= 5 min ago (or unknown)
const POLL_RECENT = 120;                    // last action <= 30 min ago
const POLL_IDLE = 300;                      // longer inactivity: he has to act before he can fly
const ACTIVE_WINDOW = 300;
const RECENT_WINDOW = 1800;
const KEY_HALT_CODES = [2, 8, 10, 13, 14, 16, 18];

function collectorKey(env) {
  return String(env.COLLECTOR_API_KEY || env.TORN_API_KEY || "");
}

function collectorBudget(env) {
  const configured = Number(env.COLLECT_MAX_POLLS);

  return Number.isFinite(configured) && configured >= 1
    ? Math.min(Math.floor(configured), COLLECT_HARD_MAX_POLLS)
    : COLLECT_DEFAULT_MAX_POLLS;
}

// When should this player be looked at again? (seconds, absolute)
function planNextPoll(obs, nowSec) {
  if (obs.state === "Traveling") {
    // He cannot do anything until he lands: wait for the landing time Torn gave us.
    return obs.until > nowSec ? Math.max(obs.until + 3, nowSec + 20) : nowSec + POLL_ACTIVE;
  }

  if (["Hospital", "Jail", "Federal"].includes(obs.state) && obs.until > nowSec) {
    return Math.min(Math.max(obs.until + 3, nowSec + POLL_ACTIVE), nowSec + 3600);
  }

  if (!(obs.laTs > 0)) return nowSec + POLL_ACTIVE;

  const idleFor = nowSec - obs.laTs;

  if (idleFor <= ACTIVE_WINDOW) return nowSec + POLL_ACTIVE;
  if (idleFor <= RECENT_WINDOW) return nowSec + POLL_RECENT;
  return nowSec + POLL_IDLE;
}

// Pure function: previous stored state + new observation => new row + facts to record.
function deriveObservation(prev, obs, nowSec) {
  const events = [];
  const prevState = prev && prev.state ? prev.state : null;
  const prevAt = prev && prev.last_polled_at ? Number(prev.last_polled_at) : null;
  const here = parseTravelDescription(obs.description);
  let flightStartedAt = prev && prev.flight_started_at ? Number(prev.flight_started_at) : null;

  const base = (type, extra) => ({
    key: obs.id + "|" + type + "|" + nowSec,
    targetId: obs.id,
    type,
    stateFrom: prevState,
    stateTo: obs.state,
    description: obs.description || null,
    country: here.country,
    direction: here.direction,
    observedAt: nowSec,
    observedAfter: prevAt,
    landingAt: null,
    landingSource: null,
    durationMin: null,
    quality: "observed",
    ...extra
  });

  const landing = obs.until > nowSec ? { landingAt: obs.until, landingSource: "api" } : {};

  if (obs.state === "Traveling") {
    if (!prevState) {
      // First time we ever see him, and he is already in the air: take-off time unknown.
      events.push(base("departure", { ...landing, quality: "in_flight" }));
      flightStartedAt = null;
    } else if (prevState !== "Traveling") {
      const guessed = inferTakeoff(here.country, obs.until, nowSec, prevAt);
      if (guessed && Math.abs(guessed - nowSec) > 20) {
        events.push(base("departure", { ...landing, observedAt: guessed, quality: "inferred" }));
        flightStartedAt = guessed;
      } else {
        events.push(base("departure", landing));
        flightStartedAt = nowSec;
      }
    } else if (prev.description && obs.description && prev.description !== obs.description) {
      // Different route between two checks: we missed a landing and a take-off. Say so, invent nothing.
      events.push(base("departure", { ...landing, quality: "in_flight" }));
      flightStartedAt = null;
    }
  } else if (prevState === "Traveling") {
    const before = parseTravelDescription(prev.description);
    let durationMin = null;

    if (flightStartedAt) {
      const minutes = Math.round((nowSec - flightStartedAt) / 60);
      durationMin = minutes >= 0 && minutes <= 12 * 60 ? minutes : null;
    }

    events.push(base("arrival", {
      country: here.country || before.country,
      direction: before.direction,
      landingAt: prev.until > 0 ? Number(prev.until) : null,
      landingSource: prev.until > 0 ? "api" : null,
      durationMin
    }));
    flightStartedAt = null;
  } else if (prevState && prevState !== obs.state) {
    events.push(base("state_change", {}));
  }

  return {
    row: {
      id: obs.id,
      name: obs.name || null,
      state: obs.state,
      description: obs.description || null,
      until: obs.until || 0,
      laTs: obs.laTs || 0,
      laStatus: obs.laStatus || null,
      at: nowSec,
      changeAt: !prevState || prevState !== obs.state || events.length ? nowSec : null,
      fs: flightStartedAt,
      next: planNextPoll(obs, nowSec)
    },
    events
  };
}

function normaliseProfile(id, data) {
  const status = data && typeof data.status === "object" && data.status ? data.status : null;

  if (!status || typeof status.state !== "string" || !status.state) return null;

  const lastAction = data.last_action && typeof data.last_action === "object" ? data.last_action : {};
  const until = Number(status.until);
  const laTs = Number(lastAction.timestamp);

  return {
    id: String(id),
    name: cleanText(data.name, 40),
    state: cleanText(status.state, 20),
    description: cleanText(status.description, 80),
    until: Number.isFinite(until) && until > 0 ? Math.floor(until) : 0,
    laTs: Number.isFinite(laTs) && laTs > 0 ? Math.floor(laTs) : 0,
    laStatus: cleanText(lastAction.status, 12)
  };
}

// Never throws; never puts the key in a message.
async function fetchTornProfile(id, key) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), COLLECT_FETCH_TIMEOUT_MS);

  try {
    const url = "https://api.torn.com/user/" + encodeURIComponent(id) +
      "?selections=profile&comment=TravelWatcher&key=" + encodeURIComponent(key);
    const response = await tornFetch(url, { signal: controller.signal });

    if (!response.ok) return { ok: false, kind: "http", code: response.status };

    let data;
    try { data = await response.json(); } catch { return { ok: false, kind: "shape", code: 0 }; }

    if (data && data.error) {
      return { ok: false, kind: "api", code: Number(data.error.code) || 0 };
    }

    const obs = normaliseProfile(id, data);

    return obs ? { ok: true, obs } : { ok: false, kind: "shape", code: 0 };
  } catch {
    return { ok: false, kind: "network", code: 0 };
  } finally {
    clearTimeout(timer);
  }
}

async function runPool(items, size, shouldStop, worker) {
  const results = new Array(items.length).fill(null);
  let next = 0;

  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (true) {
        const index = next++;
        if (index >= items.length) return;
        if (shouldStop()) continue;
        results[index] = await worker(items[index]);
      }
    })
  );

  return results;
}

function errorLabel(result) {
  return result.kind + (result.code ? ":" + result.code : "");
}

function errorBackoffSeconds(result, previousErrors) {
  if (result.kind === "api" && result.code === 6) return 3600;      // wrong player id
  return Math.min(60 * Math.pow(2, Math.min(previousErrors, 4)), 900);
}

async function collect(env, trigger, reserve = 0) {
  const startedMs = Date.now();
  const nowSec = Math.floor(startedMs / 1000);
  const summary = {
    trigger, startedAt: nowSec, due: 0, claimed: 0, polled: 0, ok: 0,
    errors: 0, events: 0, deferred: 0, halted: false, note: null, durationMs: 0
  };

  await ensureSchema(env);

  const state = (await env.DB.prepare(`SELECT * FROM collector_state WHERE id = 1`).first()) || {};
  let haltedUntil = Number(state.halted_until) || 0;
  let haltedReason = state.halted_reason || null;
  let lastError = null;
  let firstErrorLabel = null;
  const key = collectorKey(env);

  const finish = async (extraStatements) => {
    summary.durationMs = Date.now() - startedMs;

    const success = !summary.halted && summary.errors === 0;
    const statements = [
      ...(extraStatements || []),
      env.DB.prepare(`
        UPDATE collector_state SET
          last_run_at = ?, last_run_trigger = ?,
          last_success_at = CASE WHEN ? = 1 THEN ? ELSE last_success_at END,
          last_poll_at = CASE WHEN ? > 0 THEN ? ELSE last_poll_at END,
          runs_total = runs_total + 1,
          polls_total = polls_total + ?,
          errors_total = errors_total + ?,
          events_total = events_total + ?,
          halted_until = ?, halted_reason = ?,
          last_error = COALESCE(?, last_error),
          last_error_at = CASE WHEN ? IS NOT NULL THEN ? ELSE last_error_at END
        WHERE id = 1
      `).bind(
        nowSec, trigger,
        success ? 1 : 0, nowSec,
        summary.ok, nowSec,
        summary.polled, summary.errors, summary.events,
        haltedUntil, haltedReason,
        lastError, lastError, nowSec
      ),
      env.DB.prepare(`
        INSERT INTO collector_runs (started_at, duration_ms, trigger, due, polled, ok, errors, events, deferred, note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        nowSec, summary.durationMs, trigger, summary.due, summary.polled, summary.ok,
        summary.errors, summary.events, summary.deferred, summary.note
      )
    ];

    if (Math.random() < 0.05) {
      statements.push(
        env.DB.prepare(`DELETE FROM collector_runs WHERE started_at < ?`).bind(nowSec - COLLECT_RUN_KEEP_SECONDS)
      );
    }

    await env.DB.batch(statements);
    return summary;
  };

  if (!key) {
    summary.halted = true;
    summary.note = "No Torn API key configured (TORN_API_KEY / COLLECTOR_API_KEY)";
    lastError = summary.note;
    return await finish();
  }

  if (haltedUntil > nowSec) {
    summary.halted = true;
    summary.note = "Paused until " + new Date(haltedUntil * 1000).toISOString() + " (" + (haltedReason || "error") + ")";
    return await finish();
  }

  haltedUntil = 0;
  haltedReason = null;

  // 1. every watched player, once, whoever watches him
  await env.DB.prepare(`
    INSERT OR IGNORE INTO watch_targets (target_torn_id, next_poll_at, first_seen_at)
    SELECT DISTINCT t.target_torn_id, 0, ? FROM targets t WHERE ${PREMIUM_TARGET_SQL}
  `).bind(nowSec, nowSec).run();

  const dueRow = await env.DB.prepare(`
    SELECT COUNT(*) AS n FROM watch_targets w
    WHERE w.next_poll_at <= ?
      AND EXISTS (SELECT 1 FROM targets t WHERE t.target_torn_id = w.target_torn_id AND ${PREMIUM_TARGET_SQL})
  `).bind(nowSec, nowSec).first();
  summary.due = dueRow ? Number(dueRow.n) || 0 : 0;

  // 2. claim the most overdue ones (lease), within the request budget
  const budget = Math.max(1, collectorBudget(env) - reserve);
  const claimed = await env.DB.prepare(`
    UPDATE watch_targets SET next_poll_at = ?
    WHERE target_torn_id IN (
      SELECT w.target_torn_id FROM watch_targets w
      WHERE w.next_poll_at <= ?
        AND EXISTS (SELECT 1 FROM targets t WHERE t.target_torn_id = w.target_torn_id AND ${PREMIUM_TARGET_SQL})
      ORDER BY w.next_poll_at ASC, w.target_torn_id ASC
      LIMIT ?
    )
    RETURNING target_torn_id, name, state, description, until, la_ts, last_polled_at, flight_started_at, error_count
  `).bind(nowSec + COLLECT_LEASE_SECONDS, nowSec, nowSec, budget).all();

  const rows = claimed.results || [];
  summary.claimed = rows.length;
  summary.deferred = Math.max(0, summary.due - rows.length);

  if (rows.length === 0) {
    summary.note = "Nothing due";
    return await finish();
  }

  // 3. ask Torn (6 at a time), stop early if Torn tells us to
  let stopReason = null;

  const results = await runPool(
    rows,
    COLLECT_CONCURRENCY,
    () => Boolean(stopReason) || Date.now() - startedMs > COLLECT_RUN_BUDGET_MS,
    async (row) => {
      const result = await fetchTornProfile(row.target_torn_id, key);

      if (!result.ok && result.kind === "api") {
        if (KEY_HALT_CODES.includes(result.code)) stopReason = "key:" + result.code;
        else if (result.code === 5) stopReason = "rate:5";
      }

      return result;
    }
  );

  // 4. turn answers into rows + facts
  const okRows = [];
  const errRows = [];
  const releaseIds = [];
  const events = [];
  const activity = [];

  rows.forEach((row, index) => {
    const result = results[index];

    if (!result) {
      releaseIds.push(String(row.target_torn_id));
      return;
    }

    summary.polled++;

    if (result.ok) {
      summary.ok++;
      const derived = deriveObservation(row, result.obs, nowSec);
      okRows.push(derived.row);
      derived.events.forEach(e => events.push(e));
      if (result.obs.laTs > 0) {
        activity.push({ id: result.obs.id, hour: Math.floor(result.obs.laTs / 3600) });
      }
      return;
    }

    summary.errors++;
    const label = errorLabel(result);
    if (!firstErrorLabel) firstErrorLabel = label;

    errRows.push({
      id: String(row.target_torn_id),
      msg: label,
      at: nowSec,
      next: nowSec + errorBackoffSeconds(result, Number(row.error_count) || 0)
    });
  });

  summary.events = events.length;

  if (stopReason) {
    summary.halted = true;
    const isKey = stopReason.startsWith("key:");
    haltedUntil = nowSec + (isKey ? COLLECT_KEY_HALT_SECONDS : COLLECT_RATE_HALT_SECONDS);
    haltedReason = stopReason;
    summary.note = "Stopped: Torn answered " + stopReason +
      (isKey ? " (key problem) — paused 30 min" : " (rate limit) — paused 2 min");
  } else if (summary.deferred > 0) {
    summary.note = summary.deferred + " player(s) deferred to the next run (request budget " + budget + ")";
  }

  if (firstErrorLabel) {
    lastError = firstErrorLabel + (summary.errors > 1 ? " (+" + (summary.errors - 1) + " more)" : "");
  }

  // 5. one atomic write: state + facts + schedule
  const statements = [];

  if (okRows.length) {
    statements.push(env.DB.prepare(`
      UPDATE watch_targets SET
        name = COALESCE(NULLIF(json_extract(j.value, '$.name'), ''), watch_targets.name),
        state = json_extract(j.value, '$.state'),
        description = json_extract(j.value, '$.description'),
        until = json_extract(j.value, '$.until'),
        la_ts = json_extract(j.value, '$.laTs'),
        la_status = json_extract(j.value, '$.laStatus'),
        flight_started_at = json_extract(j.value, '$.fs'),
        last_polled_at = json_extract(j.value, '$.at'),
        last_change_at = COALESCE(json_extract(j.value, '$.changeAt'), watch_targets.last_change_at),
        next_poll_at = json_extract(j.value, '$.next'),
        polls = watch_targets.polls + 1,
        error_count = 0,
        last_error = NULL
      FROM json_each(?) AS j
      WHERE watch_targets.target_torn_id = json_extract(j.value, '$.id')
    `).bind(JSON.stringify(okRows)));
  }

  if (errRows.length) {
    statements.push(env.DB.prepare(`
      UPDATE watch_targets SET
        error_count = watch_targets.error_count + 1,
        last_error = json_extract(j.value, '$.msg'),
        last_error_at = json_extract(j.value, '$.at'),
        next_poll_at = json_extract(j.value, '$.next')
      FROM json_each(?) AS j
      WHERE watch_targets.target_torn_id = json_extract(j.value, '$.id')
    `).bind(JSON.stringify(errRows)));
  }

  if (releaseIds.length) {
    statements.push(env.DB.prepare(`
      UPDATE watch_targets SET next_poll_at = ?
      WHERE target_torn_id IN (SELECT value FROM json_each(?))
    `).bind(haltedUntil || nowSec, JSON.stringify(releaseIds)));
  }

  if (events.length) {
    statements.push(env.DB.prepare(`
      INSERT OR IGNORE INTO target_events (
        event_key, target_torn_id, event_type, state_from, state_to, description, country, direction,
        observed_at, observed_after, landing_at, landing_source, duration_min, quality
      )
      SELECT
        json_extract(j.value, '$.key'), json_extract(j.value, '$.targetId'), json_extract(j.value, '$.type'),
        json_extract(j.value, '$.stateFrom'), json_extract(j.value, '$.stateTo'),
        json_extract(j.value, '$.description'), json_extract(j.value, '$.country'),
        json_extract(j.value, '$.direction'), json_extract(j.value, '$.observedAt'),
        json_extract(j.value, '$.observedAfter'), json_extract(j.value, '$.landingAt'),
        json_extract(j.value, '$.landingSource'), json_extract(j.value, '$.durationMin'),
        json_extract(j.value, '$.quality')
      FROM json_each(?) AS j
    `).bind(JSON.stringify(events)));
  }

  if (activity.length) {
    statements.push(env.DB.prepare(`
      INSERT OR IGNORE INTO target_activity (target_torn_id, hour_utc)
      SELECT json_extract(j.value, '$.id'), json_extract(j.value, '$.hour')
      FROM json_each(?) AS j
    `).bind(JSON.stringify(activity)));
  }

  return await finish(statements);
}

// Public, non-sensitive heartbeat (used by /health).
async function collectorHeartbeat(env) {
  try {
    const row = await env.DB.prepare(`
      SELECT last_run_at, last_success_at, halted_until FROM collector_state WHERE id = 1
    `).first();

    const now = nowSeconds();
    const lastRunAt = row && row.last_run_at ? Number(row.last_run_at) : null;

    return {
      lastRunAt,
      lastSuccessAt: row && row.last_success_at ? Number(row.last_success_at) : null,
      running: lastRunAt !== null && now - lastRunAt <= 180,
      paused: Boolean(row && row.halted_until > now)
    };
  } catch {
    return { lastRunAt: null, lastSuccessAt: null, running: false, paused: false };
  }
}

const EVENT_RETENTION_DAYS = 400;
const MAX_EVENTS_PER_REQUEST = 50;
const EVENT_TYPES = ["departure", "arrival", "state_change"];
const KNOWN_STATES = ["Okay", "Traveling", "Abroad", "Hospital", "Jail", "Federal"];

// "Traveling to Mexico" / "Returning to Torn from Mexico" / "In Mexico"
// Flight times (minutes, standard aircraft) and aircraft speed factors: used to recognise a destination
// anywhere in Torn's wording and to rebuild a take-off time that was missed between two checks.
const TRAVEL_BASE_MIN = {
  "Mexico": 25, "Cayman Islands": 33, "Canada": 39, "Hawaii": 127, "United Kingdom": 151,
  "Argentina": 158, "Switzerland": 166, "Japan": 213, "China": 229,
  "United Arab Emirates": 257, "South Africa": 281
};
const TRAVEL_ALIASES = {
  "cayman": "Cayman Islands", "uk": "United Kingdom", "u.k.": "United Kingdom", "britain": "United Kingdom",
  "uae": "United Arab Emirates", "emirates": "United Arab Emirates", "dubai": "United Arab Emirates"
};
const PLANE_FACTORS = [1.00, 0.70, 0.50, 0.30, 0.75, 0.53, 0.38, 0.23];

function findTravelCountry(text) {
  const lower = String(text || "").toLowerCase();
  let best = null;
  const consider = (needle, canonical) => {
    const i = lower.indexOf(needle);
    if (i < 0) return;
    // word boundary on both sides, so "uk" does not match inside another word
    const before = i === 0 ? " " : lower[i - 1];
    const after = i + needle.length >= lower.length ? " " : lower[i + needle.length];
    if (/[a-z]/.test(before) || /[a-z]/.test(after)) return;
    if (!best || i < best.i) best = { i, canonical };
  };
  Object.keys(TRAVEL_BASE_MIN).forEach(name => consider(name.toLowerCase(), name));
  Object.keys(TRAVEL_ALIASES).forEach(alias => consider(alias, TRAVEL_ALIASES[alias]));
  return best ? best.canonical : null;
}

function parseTravelDescription(description) {
  const text = String(description || "").replace(/\s+/g, " ").trim();
  let match;
  const known = findTravelCountry(text);

  const fromTo = text.match(/^travell?ing from (.{2,40}?) to (.{2,40})$/i);
  if (fromTo) {
    const a = fromTo[1].trim(), b = fromTo[2].trim();
    if (/^torn$/i.test(b)) return { country: findTravelCountry(a) || a, direction: "return" };
    if (/^torn$/i.test(a)) return { country: findTravelCountry(b) || b, direction: "outbound" };
  }

  if (/^returning to\b/i.test(text)) {
    match = text.match(/\bfrom (.{2,40})$/i);
    return { country: known || (match ? match[1].trim() : null), direction: "return" };
  }

  if (/^travell?ing\b/i.test(text)) {
    match = text.match(/^travell?ing to (.{2,40})$/i);
    return { country: known || (match ? match[1].trim() : null), direction: "outbound" };
  }

  if ((match = text.match(/^In (.{2,40})$/i))) {
    return { country: known || match[1].trim(), direction: null };
  }

  return { country: known, direction: null };
}

// Take-off rebuilt from the landing time Torn gave us. Only when ONE aircraft fits the window between
// the last check (still on the ground) and this one: otherwise nothing is invented.
function inferTakeoff(country, untilSec, nowSec, prevAtSec) {
  const base = country ? TRAVEL_BASE_MIN[country] : 0;
  if (!base || !(untilSec > nowSec) || !(prevAtSec > 0)) return null;

  const found = [];
  PLANE_FACTORS.forEach(f => {
    const start = untilSec - Math.round(base * f * 60);
    if (start >= prevAtSec - 45 && start <= nowSec + 15) found.push(start);
  });

  const distinct = found.filter((v, i) => found.findIndex(w => Math.abs(w - v) <= 30) === i);
  if (distinct.length !== 1) return null;

  return Math.min(nowSec, Math.max(prevAtSec, distinct[0]));
}

let countriesBackfilledAt = 0;

// Derived column only: fills the destination of old rows whose wording the former parser did not understand.
async function backfillCountries(env) {
  if (Date.now() - countriesBackfilledAt < 3600 * 1000) return;
  countriesBackfilledAt = Date.now();

  try {
    for (const table of ["travel_events", "target_events"]) {
      const rows = await env.DB.prepare(`
        SELECT id, description FROM ${table}
        WHERE country IS NULL AND description IS NOT NULL AND description <> ''
        LIMIT 400
      `).all();

      const statements = [];
      for (const r of (rows.results || [])) {
        const p = parseTravelDescription(r.description);
        if (p.country) {
          statements.push(env.DB.prepare(`UPDATE ${table} SET country = ?, direction = COALESCE(direction, ?) WHERE id = ?`).bind(p.country, p.direction, r.id));
        }
      }
      for (let i = 0; i < statements.length; i += 40) await env.DB.batch(statements.slice(i, i + 40));
    }
  } catch (error) {
    console.error("Country backfill error:", error?.stack || String(error));
  }
}

function cleanText(value, max) {
  return typeof value === "string"
    ? value.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, max)
    : "";
}

function cleanInt(value, min, max) {
  if (value === null || value === undefined || value === "") return null;

  const n = Number(value);
  return Number.isFinite(n) && n >= min && n <= max ? Math.round(n) : null;
}

function validPrefs(prefs) {
  if (!prefs || typeof prefs !== "object" || Array.isArray(prefs)) return null;

  const theme = ["light", "dark", "system"].includes(prefs.theme) ? prefs.theme : "dark";
  const alerts = prefs.alerts && typeof prefs.alerts === "object" ? prefs.alerts : {};

  return {
    theme,
    alerts: {
      departure: alerts.departure !== false,
      arrival: alerts.arrival !== false,
      return: alerts.return !== false,
      mute: Array.isArray(alerts.mute)
        ? alerts.mute.map(String).filter(v => /^\d{1,12}$/.test(v)).slice(0, 200)
        : []
    }
  };
}

// A target is collected / shown by the server only when at least one PREMIUM member watches it.
// Premium = administrator, or an unexpired credit. One "?" = now (seconds).
const PREMIUM_TARGET_SQL = `EXISTS (SELECT 1 FROM users pu JOIN accounts pa ON pa.torn_user_id = pu.torn_user_id WHERE pu.id = t.user_id AND pa.active = 1 AND (pa.role = 'admin' OR EXISTS (SELECT 1 FROM premium pp WHERE pp.account_id = pa.id AND pp.premium_until > ?)))`;

async function premiumInfo(env, account) {
  if (account && account.role === "admin") return { active: true, admin: true, until: null };

  const row = await env.DB.prepare(`SELECT premium_until FROM premium WHERE account_id = ?`).bind(account.id).first();
  const until = row ? Number(row.premium_until) : null;

  return { active: Boolean(until && until > nowSeconds()), admin: false, until };
}

// Credits are idempotent on `ref` (a Torn log id later): the same reference can never be credited twice.
async function premiumCredit(env, accountId, hours, source, ref, note, createdBy) {
  const now = nowSeconds();

  const results = await env.DB.batch([
    env.DB.prepare(`
      INSERT OR IGNORE INTO premium_credits (account_id, hours, source, ref, note, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(accountId, hours, source, ref, note || null, createdBy || null, now),
    env.DB.prepare(`
      INSERT INTO premium (account_id, premium_until, updated_at)
      SELECT ?, MAX(COALESCE((SELECT premium_until FROM premium WHERE account_id = ?), 0), ?) + ?, ?
      WHERE changes() = 1
      ON CONFLICT(account_id) DO UPDATE SET
        premium_until = excluded.premium_until,
        updated_at = excluded.updated_at
    `).bind(accountId, accountId, now, hours * 3600, now)
  ]);

  const changes = results && results[0] && results[0].meta ? results[0].meta.changes : undefined;

  return { applied: changes === undefined ? true : Number(changes) === 1 };
}

// KEYVAULT-BEGIN
const KEY_FORMAT = /^[A-Za-z0-9]{16}$/;

function vaultAvailable(env) {
  return typeof env.KEY_ENCRYPTION_SECRET === "string" && env.KEY_ENCRYPTION_SECRET.length >= 32;
}

function bytesToB64(bytes) {
  let out = "";
  for (const b of bytes) out += String.fromCharCode(b);
  return btoa(out);
}

function b64ToBytes(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let vaultKeyCache = null;

async function vaultKey(env) {
  const secret = env.KEY_ENCRYPTION_SECRET;
  if (vaultKeyCache && vaultKeyCache.secret === secret) return vaultKeyCache.key;

  const base = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode("ttw-key-vault"), info: encoder.encode("user-api-key-v1") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  vaultKeyCache = { secret, key };
  return key;
}

// The account id is bound to the ciphertext (AAD): a stored key cannot be moved to another account.
async function encryptUserKey(env, accountId, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("ttw-user-key:" + accountId) },
    await vaultKey(env),
    encoder.encode(plain)
  );
  return "v1." + bytesToB64(iv) + "." + bytesToB64(new Uint8Array(cipher));
}

async function decryptUserKey(env, accountId, stored) {
  const parts = String(stored).split(".");
  if (parts.length !== 3 || parts[0] !== "v1") throw new Error("Unsupported key format");

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(parts[1]), additionalData: encoder.encode("ttw-user-key:" + accountId) },
    await vaultKey(env),
    b64ToBytes(parts[2])
  );

  return new TextDecoder().decode(plain);
}

// One call to Torn with a user's key. The key is never logged and never part of an error message.
async function tornKeyRequest(path, selections, key) {
  const url = new URL("https://api.torn.com/" + path);
  url.searchParams.set("selections", selections);
  url.searchParams.set("comment", "TravelWatcher");
  url.searchParams.set("key", key);

  try {
    const response = await tornFetch(url.toString());
    const data = await response.json();
    return { httpStatus: response.status, data: data && typeof data === "object" ? data : null };
  } catch {
    return { httpStatus: 0, data: null };
  }
}

function tornKeyErrorMessage(code) {
  switch (Number(code)) {
    case 2: return "Torn says this key is incorrect. Check that you copied all 16 characters.";
    case 5: return "Torn is rate-limiting requests right now. Try again in a minute.";
    case 8: case 9: case 14: case 17: return "The Torn API is temporarily unavailable. Try again later.";
    case 10: return "This key cannot be used while its owner is in federal jail.";
    case 13: return "Torn disabled this key because its owner has been inactive for more than 7 days.";
    case 16: return "This key does not have enough access. Create a key with Public access.";
    case 18: return "This key is paused. Unpause it in your Torn API settings.";
    default: return "Torn did not accept this key.";
  }
}
// KEYVAULT-END

// ---- Automatic Premium from Torn log: "Item receive" (log 4103), item 206 (Xanax), message exactly "TTW".
// Personal Xanax (any other message) are ignored. Idempotent on the Torn log entry id.
// The word the sender must write as the message. Change it here ONLY (the site text follows automatically).
const PREMIUM_KEYWORD = "scope";
const XANAX_ITEM_ID = 206;
const XANAX_HOURS_EACH = 168;
const XANAX_HOURS_BONUS = 336;      // same faction or same company as the owner: 1 Xanax = 14 days
const XANAX_MAX_HOURS = 8760;       // one year per entry; above: manual review
const AFFIL_MAX_AGE = 24 * 3600;    // faction/company of a member is re-checked at most once a day
const OWNER_AFFIL_MAX_AGE = 6 * 3600;
const SITE_URL = "https://app.tornscope.com"; // public address of the site (links opened from the script)
const XANAX_CHECK_EVERY = 110;      // seconds between two log reads
const XANAX_RESERVE = 14;           // subrequests kept aside for it in a cron run

// "Scope", "SCOPE", " s c o p e ", "scope please!", "TornScope" all match: accents, case, spaces and punctuation are ignored.
function normalizeWord(text) {
  return String(text == null ? "" : text).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function xanaxQty(entry) {
  if (!entry || Number(entry.log) !== 4103 || !entry.data || typeof entry.data !== "object") return 0;
  if (!normalizeWord(entry.data.message).includes(normalizeWord(PREMIUM_KEYWORD))) return 0;

  let qty = 0;
  for (const item of Array.isArray(entry.data.items) ? entry.data.items : []) {
    if (item && Number(item.id) === XANAX_ITEM_ID) qty += Math.max(0, Math.floor(Number(item.qty) || 0));
  }

  return qty;
}

// ---- Faction / company bonus: 1 Xanax = 14 days for members of the owner's faction or company.
// Read from the Torn API (profile of the member, with the owner's key). Nothing else is stored.
async function fetchAffiliation(env, tornId) {
  try {
    const url = new URL("https://api.torn.com/user/" + encodeURIComponent(tornId));
    url.searchParams.set("selections", "profile");
    url.searchParams.set("key", env.TORN_API_KEY);
    const res = await tornFetch(url.toString());
    const data = await res.json();
    if (!res.ok || !data || data.error) return null;
    return {
      factionId: Math.max(0, Math.floor(Number(data.faction && data.faction.faction_id) || 0)),
      companyId: Math.max(0, Math.floor(Number(data.job && data.job.company_id) || 0))
    };
  } catch {
    return null;
  }
}

async function ownerAffiliation(env) {
  const now = nowSeconds();
  const row = await env.DB.prepare(`SELECT faction_id, company_id, checked_at FROM owner_affil WHERE id = 1`).first();
  const stored = row ? { factionId: Number(row.faction_id), companyId: Number(row.company_id) } : null;

  if (row && now - Number(row.checked_at) < OWNER_AFFIL_MAX_AGE) return stored;

  const fresh = await fetchAffiliation(env, ADMIN_TORN_ID);
  if (!fresh) return stored;

  await env.DB.prepare(`
    INSERT INTO owner_affil (id, faction_id, company_id, checked_at) VALUES (1, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET faction_id = excluded.faction_id, company_id = excluded.company_id, checked_at = excluded.checked_at
  `).bind(fresh.factionId, fresh.companyId, now).run();

  return fresh;
}

async function refreshAffiliation(env, accountId, tornId) {
  const owner = await ownerAffiliation(env);
  const mine = await fetchAffiliation(env, tornId);
  if (!owner || !mine) return null;

  const sameFaction = owner.factionId > 0 && mine.factionId === owner.factionId;
  const sameCompany = owner.companyId > 0 && mine.companyId === owner.companyId;

  await env.DB.prepare(`
    INSERT INTO account_affil (account_id, same_faction, same_company, checked_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(account_id) DO UPDATE SET same_faction = excluded.same_faction, same_company = excluded.same_company, checked_at = excluded.checked_at
  `).bind(accountId, sameFaction ? 1 : 0, sameCompany ? 1 : 0, nowSeconds()).run();

  return { sameFaction, sameCompany };
}

async function storedAffiliation(env, accountId) {
  const row = await env.DB.prepare(`SELECT same_faction, same_company, checked_at FROM account_affil WHERE account_id = ?`).bind(accountId).first();
  return row ? { sameFaction: row.same_faction === 1, sameCompany: row.same_company === 1, checkedAt: Number(row.checked_at) } : null;
}

// maxAgeSec = 0 forces a fresh check; if Torn cannot be reached the last known answer is used.
async function affiliationFor(env, accountId, tornId, maxAgeSec) {
  const row = await storedAffiliation(env, accountId);
  if (row && nowSeconds() - row.checkedAt < maxAgeSec) return row;

  const fresh = await refreshAffiliation(env, accountId, tornId);
  if (fresh) return fresh;

  return row || { sameFaction: false, sameCompany: false };
}

const affiliationBonus = (a) => a && a.sameFaction && a.sameCompany ? "both" : a && a.sameFaction ? "faction" : a && a.sameCompany ? "company" : null;
const hoursPerXanaxFor = (a) => affiliationBonus(a) ? XANAX_HOURS_BONUS : XANAX_HOURS_EACH;

// ================= Restock radar (closed beta): Cruise Line companies =================
// One request per company returns every employee with status, travel and last action. We keep the current state of
// each employee and a history of flights: take-off = middle of the window between two reads, aircraft from
// plane_image_type. Only changes are written (D1 Free plan: 100k writes per day).
const RADAR_COMPANY_TYPE = 15;     // Cruise Line
const RADAR_MAX_PER_RUN = 6;       // companies read per cron run on the Free plan (env.RADAR_MAX raises it on a paid plan)
const RADAR_KEEP_DAYS = 60;

function radarMax(env, reserve) {
  const cfg = Number(env.RADAR_MAX);
  const paid = Number.isFinite(cfg) && cfg > RADAR_MAX_PER_RUN;   // Workers Paid: 1000 subrequests per run instead of 50
  const cap = Number.isFinite(cfg) && cfg >= 1 ? Math.min(Math.floor(cfg), 60) : RADAR_MAX_PER_RUN;
  return Math.max(2, Math.min(cap, (paid ? 200 : 30) - reserve));
}

// How soon should this company be read again? Someone active in the last 10 minutes can take off any time.
function radarInterval(players, now, fast) {
  let best = fast ? 600 : 1200;
  for (const p of players) {
    if (p.state === "Traveling") { best = Math.min(best, fast ? 60 : 120); continue; }
    const idle = now - p.lastAction;
    best = Math.min(best, fast
      ? (idle < 600 ? 30 : idle < 3600 ? 60 : idle < 28800 ? 180 : 600)
      : (idle < 600 ? 60 : idle < 3600 ? 180 : idle < 28800 ? 600 : 1200));
  }
  return best;
}

function radarRoster(data) {
  const c = data && data.company && typeof data.company === "object" ? data.company : null;
  if (!c) return null;
  const raw = c.employees;
  const entries = Array.isArray(raw) ? raw.map(e => [e && e.id, e]) : raw && typeof raw === "object" ? Object.entries(raw) : [];
  const players = [];
  for (const [id, e] of entries) {
    if (!/^\d+$/.test(String(id)) || !e) continue;
    const st = e.status || {}, la = e.last_action || {};
    const desc = typeof st.description === "string" ? st.description.slice(0, 120) : "";
    const parsed = parseTravelDescription(desc);
    players.push({
      id: Number(id), name: typeof e.name === "string" ? e.name.slice(0, 40) : "", position: typeof e.position === "string" ? e.position.slice(0, 30) : "",
      state: typeof st.state === "string" ? st.state.slice(0, 24) : "", description: desc,
      lastAction: Math.max(0, Math.floor(Number(la.timestamp) || 0)),
      country: parsed.country || null, direction: parsed.direction || null,
      planeType: typeof st.plane_image_type === "string" ? st.plane_image_type.slice(0, 24) : ""
    });
  }
  return {
    name: typeof c.name === "string" ? c.name.slice(0, 60) : "", type: Math.floor(Number(c.company_type) || 0),
    rating: Math.floor(Number(c.rating) || 0), players
  };
}

// Pure: compare the new roster with what we stored. Returns what to write.
function radarDiff(prev, players, winStart, now) {
  const out = { upserts: [], flights: [], landings: [], present: new Set() };
  for (const m of players) {
    out.present.add(m.id);
    const p = prev.get(m.id);
    let takeoff = 0;
    if (m.state === "Traveling") {
      if (p && p.state === "Traveling" && p.description === m.description) takeoff = Number(p.takeoff_at) || 0;
      else if (p && p.state !== "Traveling" && winStart > 0) {
        takeoff = Math.round((winStart + now) / 2);
        const f = flightFromType(m.country, m.planeType);
        out.flights.push({ playerId: m.id, takeoffAt: takeoff, country: m.country, direction: m.direction, planeType: m.planeType, plane: f.plane, duration: f.duration, winStart, winEnd: now });
      }
    } else if (p && p.state === "Traveling" && Number(p.takeoff_at) > 0) {
      out.landings.push({ playerId: m.id, takeoffAt: Number(p.takeoff_at) });
    }
    const changed = !p || p.state !== m.state || p.description !== m.description || (p.plane_type || "") !== m.planeType
      || p.name !== m.name || p.position !== m.position || Math.abs(Number(p.last_action) - m.lastAction) > 300 || Number(p.takeoff_at) !== takeoff;
    if (changed) out.upserts.push({ ...m, takeoffAt: takeoff });
  }
  return out;
}

async function radarCollect(env, reserve = 0, forceLimit = 0) {
  const out = { ran: false, companies: 0, players: 0, flights: 0, landings: 0, errors: 0, reserve: 0 };
  if (!env.TORN_API_KEY) return out;
  const now = nowSeconds();
  const limit = forceLimit > 0 ? forceLimit : radarMax(env, reserve);

  const due = await env.DB.prepare(`
    SELECT company_id, last_read_at, fail_count FROM radar_companies
    WHERE active = 1 AND next_read_at <= ? ORDER BY next_read_at ASC, company_id ASC LIMIT ?
  `).bind(now, limit).all();
  const list = due.results || [];
  if (!list.length) return out;
  out.ran = true;
  out.reserve = list.length + 3; // 1 due query + 1 players query + fetches + up to 2 batches

  const ids = list.map(r => Number(r.company_id));
  const prevRows = await env.DB.prepare(`SELECT * FROM radar_players WHERE company_id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all();
  const prevBy = new Map();
  for (const r of prevRows.results || []) {
    const k = Number(r.company_id);
    if (!prevBy.has(k)) prevBy.set(k, new Map());
    prevBy.get(k).set(Number(r.player_id), r);
  }

  const fetched = await Promise.all(list.map(async (row) => {
    try {
      const url = new URL("https://api.torn.com/company/" + encodeURIComponent(row.company_id));
      url.searchParams.set("selections", "profile");
      url.searchParams.set("comment", "TravelWatcher");
      url.searchParams.set("timestamp", String(now));
      url.searchParams.set("key", env.TORN_API_KEY);
      const res = await tornFetch(url.toString());
      const data = await res.json();
      if (!res.ok || !data || typeof data !== "object") return { row, error: "HTTP " + res.status };
      if (data.error) return { row, error: "API " + (data.error.code || "?"), code: Number(data.error.code) || 0 };
      return { row, data };
    } catch {
      return { row, error: "network" };
    }
  }));

  const statements = [];
  for (const f of fetched) {
    const cid = Number(f.row.company_id);
    out.companies++;
    if (f.error) {
      out.errors++;
      const fails = Number(f.row.fail_count || 0) + 1;
      const dead = f.code === 6 && fails >= 3;   // "Incorrect ID" three times: not a company
      statements.push(env.DB.prepare(`UPDATE radar_companies SET last_error = ?, fail_count = ?, next_read_at = ?, active = ? WHERE company_id = ?`)
        .bind(f.error, fails, now + Math.min(1800, 120 * fails), dead ? 0 : 1, cid));
      continue;
    }
    const roster = radarRoster(f.data);
    if (!roster) {
      out.errors++;
      statements.push(env.DB.prepare(`UPDATE radar_companies SET last_error = ?, fail_count = fail_count + 1, next_read_at = ? WHERE company_id = ?`).bind("Unexpected answer", now + 300, cid));
      continue;
    }
    if (roster.type !== RADAR_COMPANY_TYPE) {
      statements.push(env.DB.prepare(`UPDATE radar_companies SET name = ?, company_type = ?, rating = ?, active = 0, last_error = ?, last_read_at = ? WHERE company_id = ?`)
        .bind(roster.name, roster.type, roster.rating, "Not a Cruise Line", now, cid));
      continue;
    }

    const prev = prevBy.get(cid) || new Map();
    const lastRead = Number(f.row.last_read_at) || 0;
    const winStart = lastRead > 0 && now - lastRead <= 1800 ? lastRead : 0;
    const diff = radarDiff(prev, roster.players, winStart, now);

    for (const p of diff.upserts) {
      statements.push(env.DB.prepare(`
        INSERT INTO radar_players (player_id, company_id, name, position, state, description, last_action, country, direction, plane_type, takeoff_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(player_id) DO UPDATE SET company_id = excluded.company_id, name = excluded.name, position = excluded.position, state = excluded.state,
          description = excluded.description, last_action = excluded.last_action, country = excluded.country, direction = excluded.direction,
          plane_type = excluded.plane_type, takeoff_at = excluded.takeoff_at, updated_at = excluded.updated_at
      `).bind(p.id, cid, p.name, p.position, p.state, p.description, p.lastAction, p.country, p.direction, p.planeType, p.takeoffAt, now));
    }
    for (const fl of diff.flights) {
      out.flights++;
      statements.push(env.DB.prepare(`
        INSERT OR IGNORE INTO radar_flights (player_id, takeoff_at, company_id, country, direction, plane_type, plane, duration, win_start, win_end, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(fl.playerId, fl.takeoffAt, cid, fl.country, fl.direction, fl.planeType, fl.plane, fl.duration, fl.winStart, fl.winEnd, now));
    }
    for (const l of diff.landings) {
      out.landings++;
      statements.push(env.DB.prepare(`UPDATE radar_flights SET landed_seen_at = ? WHERE player_id = ? AND takeoff_at = ? AND landed_seen_at = 0`).bind(now, l.playerId, l.takeoffAt));
    }
    for (const id of prev.keys()) {
      if (!diff.present.has(id)) statements.push(env.DB.prepare(`DELETE FROM radar_players WHERE player_id = ? AND company_id = ?`).bind(id, cid));
    }
    out.players += roster.players.length;
    statements.push(env.DB.prepare(`
      UPDATE radar_companies SET name = ?, company_type = ?, rating = ?, employees = ?, last_read_at = ?, next_read_at = ?, last_error = NULL, fail_count = 0 WHERE company_id = ?
    `).bind(roster.name, roster.type, roster.rating, roster.players.length, now, now + radarInterval(roster.players, now, Number(env.RADAR_MAX) > RADAR_MAX_PER_RUN) - 5, cid));
  }

  // old history
  if (now % 3600 < 60) statements.push(env.DB.prepare(`DELETE FROM radar_flights WHERE created_at < ?`).bind(now - RADAR_KEEP_DAYS * 86400));

  for (let i = 0; i < statements.length; i += 80) await env.DB.batch(statements.slice(i, i + 80));
  return out;
}


// What the Radar page shows: employees in flight, a summary per destination, and the latest flights recorded.
async function radarPayload(env) {
  const now = nowSeconds();
  const one = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).first()) || {};
  const many = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results || [];

  const pl = await one(`SELECT COUNT(*) AS n, SUM(state = 'Traveling') AS flying FROM radar_players`);
  const co = await one(`SELECT COUNT(*) AS n, SUM(active = 1) AS a, MAX(last_read_at) AS last FROM radar_companies`);
  const fl = await one(`SELECT COUNT(*) AS n, SUM(created_at > ?) AS last24h, SUM(landed_seen_at > 0) AS landed FROM radar_flights`, now - 86400);

  const flyingRows = await many(`
    SELECT p.player_id, p.name, p.position, p.country, p.direction, p.plane_type, p.takeoff_at, p.last_action, c.name AS company
    FROM radar_players p LEFT JOIN radar_companies c ON c.company_id = p.company_id
    WHERE p.state = 'Traveling' ORDER BY p.takeoff_at DESC, p.name COLLATE NOCASE LIMIT 300
  `);
  const flying = flyingRows.map(r => {
    const f = flightFromType(r.country, r.plane_type);
    const takeoffAt = Number(r.takeoff_at) || 0;
    return { id: String(r.player_id), name: r.name, position: r.position, company: r.company, country: r.country, direction: r.direction,
      plane: f.plane, takeoffAt, duration: f.duration, landingAt: takeoffAt > 0 && f.duration > 0 ? takeoffAt + f.duration : 0, lastAction: Number(r.last_action) };
  });

  const byCountry = new Map();
  for (const f of flying) {
    const key = (f.country || "?") + "|" + (f.direction === "return" ? "return" : "outbound");
    const e = byCountry.get(key) || { country: f.country || "?", direction: f.direction === "return" ? "return" : "outbound", count: 0, withLanding: 0, firstLanding: 0, lastLanding: 0 };
    e.count++;
    if (f.landingAt > 0) { e.withLanding++; e.firstLanding = e.firstLanding ? Math.min(e.firstLanding, f.landingAt) : f.landingAt; e.lastLanding = Math.max(e.lastLanding, f.landingAt); }
    byCountry.set(key, e);
  }

  const recent = await many(`
    SELECT f.player_id, f.takeoff_at, f.country, f.direction, f.plane, f.duration, f.win_start, f.win_end, f.landed_seen_at, p.name, c.name AS company
    FROM radar_flights f
    LEFT JOIN radar_players p ON p.player_id = f.player_id
    LEFT JOIN radar_companies c ON c.company_id = f.company_id
    ORDER BY f.takeoff_at DESC LIMIT 100
  `);

  return {
    ok: true, now,
    stats: { companies: co.n || 0, activeCompanies: co.a || 0, lastReadAt: co.last || 0, players: pl.n || 0, flying: pl.flying || 0, flights: fl.n || 0, flights24h: fl.last24h || 0, landed: fl.landed || 0 },
    flying,
    countries: Array.from(byCountry.values()).sort((a, b) => b.count - a.count),
    recent: recent.map(r => ({ id: String(r.player_id), name: r.name, company: r.company, takeoffAt: Number(r.takeoff_at), country: r.country, direction: r.direction,
      plane: r.plane, duration: Number(r.duration), windowSec: Math.max(0, Number(r.win_end) - Number(r.win_start)), landedSeenAt: Number(r.landed_seen_at) }))
  };
}

// ================= Foreign stock feed (closed beta; only runs when STOCK_FEED_URL is set) =================
// One request per minute to a public stock export (YATA format: {"stocks": {code: {update, stocks: [{id,name,quantity,cost}]}}}).
// We keep the latest snapshot of each country (1 row) and every RESTOCK we notice: an item whose quantity went UP between two
// updates. Stock only goes down when people buy, so any increase is a restock. The restock time is known to within the gap
// between the two updates (about 1-2 minutes). Market values come from the Torn API (items), refreshed every 6 hours.
const STOCK_KEEP_DAYS = 30;
const STOCK_PRICES_EVERY = 1800;
const STOCK_COUNTRIES = {
  mex: "Mexico", cay: "Cayman Islands", can: "Canada", haw: "Hawaii", uni: "United Kingdom", arg: "Argentina",
  swi: "Switzerland", jap: "Japan", chi: "China", uae: "United Arab Emirates", sou: "South Africa"
};

// Pure: compare the previous snapshot of a country with the new one.
function stockDiff(prevItems, nextItems, prevAt, seenAt) {
  const before = new Map((prevItems || []).map(r => [Number(r[0]), r]));
  const events = [];
  for (const r of nextItems) {
    const old = before.get(Number(r[0]));
    if (old && Number(r[2]) > Number(old[2])) {
      events.push({ itemId: Number(r[0]), name: r[1], prevAt, seenAt, before: Number(old[2]), after: Number(r[2]), cost: Number(r[3]) || 0 });
    }
  }
  return events;
}

function stockParse(data) {
  if (!data || typeof data !== "object" || !data.stocks || typeof data.stocks !== "object") return null;
  const out = {};
  for (const [code, c] of Object.entries(data.stocks)) {
    if (!STOCK_COUNTRIES[code] || !c || typeof c !== "object" || !Array.isArray(c.stocks)) continue;
    const update = Number(c.update);
    if (!Number.isFinite(update) || update <= 0) continue;
    const items = [];
    for (const it of c.stocks) {
      const id = Number(it && it.id), qty = Number(it && it.quantity), cost = Number(it && it.cost);
      if (!Number.isInteger(id) || id <= 0 || !Number.isFinite(qty) || qty < 0 || !Number.isFinite(cost) || cost < 0) continue;
      items.push([id, String(it.name || "").slice(0, 60), Math.floor(qty), Math.floor(cost)]);
    }
    if (items.length) out[code] = { update, items };
  }
  return Object.keys(out).length ? out : null;
}

async function stockCollect(env) {
  const out = { ran: false, countries: 0, events: 0, error: null, reserve: 0 };
  const feed = String(env.STOCK_FEED_URL || "");
  if (!/^https:\/\//.test(feed)) return out;
  out.ran = true; out.reserve = 3;
  const now = nowSeconds();
  let data = null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(feed, { headers: { Accept: "application/json", "User-Agent": "TornScope/1.0 (stock watcher, 1 request per minute)" }, signal: controller.signal });
      if (!res.ok) { out.error = "HTTP " + res.status; return out; }
      data = await res.json();
    } finally { clearTimeout(timer); }
  } catch { out.error = "network"; return out; }
  const parsed = stockParse(data);
  if (!parsed) { out.error = "format"; return out; }

  const rows = (await env.DB.prepare("SELECT country, updated_at, items FROM stock_snapshot").all()).results || [];
  const prev = new Map(rows.map(r => [r.country, r]));
  const statements = [];
  for (const [code, c] of Object.entries(parsed)) {
    const old = prev.get(code);
    if (old && Number(old.updated_at) >= c.update) continue;
    out.countries++;
    if (old) {
      let oldItems = []; try { oldItems = JSON.parse(old.items); } catch { oldItems = []; }
      for (const e of stockDiff(oldItems, c.items, Number(old.updated_at), c.update)) {
        out.events++;
        statements.push(env.DB.prepare("INSERT INTO stock_events (country, item_id, name, prev_at, seen_at, qty_before, qty_after, cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
          .bind(code, e.itemId, e.name, e.prevAt, e.seenAt, e.before, e.after, e.cost));
      }
    }
    {
      const oldQty = new Map();
      if (old) { try { for (const r of JSON.parse(old.items)) oldQty.set(Number(r[0]), Number(r[2])); } catch { /* ignore */ } }
      for (const r of c.items) {
        const pq = oldQty.get(Number(r[0]));
        if (pq === r[2]) continue;
        statements.push(env.DB.prepare("INSERT INTO stock_hist (country, item_id, ts, qty) VALUES (?, ?, ?, ?)").bind(code, r[0], c.update, r[2]));
        if (pq === undefined) continue;
        if (r[2] > pq) {
          statements.push(env.DB.prepare("UPDATE stock_cycle SET end_at = ? WHERE country = ? AND item_id = ? AND end_at = 0").bind(c.update, code, r[0]));
          statements.push(env.DB.prepare("INSERT INTO stock_cycle (country, item_id, start_at, qty_start) VALUES (?, ?, ?, ?)").bind(code, r[0], c.update, r[2]));
        } else if (r[2] === 0) {
          statements.push(env.DB.prepare("UPDATE stock_cycle SET soldout_at = ? WHERE country = ? AND item_id = ? AND end_at = 0 AND soldout_at = 0").bind(c.update, code, r[0]));
        }
      }
    }
    statements.push(env.DB.prepare("INSERT INTO stock_snapshot (country, updated_at, items) VALUES (?, ?, ?) ON CONFLICT(country) DO UPDATE SET updated_at = excluded.updated_at, items = excluded.items")
      .bind(code, c.update, JSON.stringify(c.items)));
  }
  if (now % 3600 < 60) {
    statements.push(env.DB.prepare("DELETE FROM stock_events WHERE seen_at < ?").bind(now - STOCK_KEEP_DAYS * 86400));
    statements.push(env.DB.prepare("DELETE FROM stock_hist WHERE ts < ?").bind(now - (STOCK_KEEP_DAYS + 1) * 86400));
    statements.push(env.DB.prepare("DELETE FROM stock_cycle WHERE start_at < ?").bind(now - (STOCK_KEEP_DAYS + 1) * 86400));
    statements.push(env.DB.prepare("DELETE FROM price_hist WHERE ts < ?").bind(now - (STOCK_KEEP_DAYS + 1) * 86400));
  }
  statements.push(env.DB.prepare("INSERT INTO stock_state (k, v) VALUES ('ok_at', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(String(now)));
  try { await env.DB.batch(statements); } catch (error) { out.error = "db"; console.error("Stock write failed:", error?.name || "error"); return out; }
  try { await stockPrices(env, parsed, now); } catch (error) { console.error("Stock prices failed:", error?.name || "error"); }
  return out;
}

// Market values (profit = market value - shop cost). Torn API, owner key, at most every 6 hours (retry after 15 minutes).
async function stockPrices(env, parsed, now) {
  const st = await env.DB.prepare("SELECT v FROM stock_state WHERE k = 'prices_next'").first();
  if (st && Number(st.v) > now) return;
  const ids = [...new Set(Object.values(parsed).flatMap(c => c.items.map(r => r[0])))];
  let okAll = true;
  const rowsOut = [];
  for (let i = 0; i < ids.length; i += 40) {
    const chunk = ids.slice(i, i + 40);
    try {
      const url = "https://api.torn.com/torn/" + chunk.join(",") + "?selections=items&comment=TravelWatcher&key=" + encodeURIComponent(env.TORN_API_KEY);
      const res = await tornFetch(url);
      const data = await res.json();
      if (!res.ok || !data || data.error || !data.items || typeof data.items !== "object") { okAll = false; continue; }
      for (const [id, it] of Object.entries(data.items)) {
        const mv = Number(it && it.market_value);
        if (Number.isFinite(mv) && mv >= 0) rowsOut.push([Number(id), String(it.name || "").slice(0, 60), Math.floor(mv), String(it.type || "").slice(0, 20)]);
      }
    } catch { okAll = false; }
  }
  const statements = rowsOut.map(r => env.DB.prepare("INSERT INTO item_prices (item_id, name, market_value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET name = excluded.name, market_value = excluded.market_value, updated_at = excluded.updated_at").bind(r[0], r[1], r[2], now));
  {
    const oldP = new Map(((await env.DB.prepare("SELECT item_id, market_value FROM item_prices").all()).results || []).map(r => [Number(r.item_id), Number(r.market_value)]));
    for (const r of rowsOut) if (oldP.get(r[0]) !== r[2]) statements.push(env.DB.prepare("INSERT INTO price_hist (item_id, ts, value) VALUES (?, ?, ?)").bind(r[0], now, r[2]));
  }
  for (const r of rowsOut) if (r[3]) statements.push(env.DB.prepare("INSERT INTO item_types (item_id, type) VALUES (?, ?) ON CONFLICT(item_id) DO UPDATE SET type = excluded.type").bind(r[0], r[3]));
  statements.push(env.DB.prepare("INSERT INTO stock_state (k, v) VALUES ('prices_next', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(String(now + (okAll ? STOCK_PRICES_EVERY : 900))));
  await env.DB.batch(statements);
}

// Next restock = last restock + the usual gap between restocks (median of what we observed). If that moment has passed
// without a restock, move to the next multiple. Confidence grows with the number of gaps and falls when they vary a lot.
function stockNext(last, med, gaps, now) {
  if (!last || !med || gaps.length < 1) return { nextRestockAt: 0, nextConfidence: 0 };
  const k = Math.max(1, Math.ceil((now - last) / med));
  const dev = gaps.map(g => Math.abs(g - med)).sort((a, b) => a - b);
  const mad = dev[Math.floor(dev.length / 2)];
  const conf = Math.min(1, gaps.length / 6) * Math.max(0, 1 - 2 * mad / med);
  return { nextRestockAt: last + k * med, nextConfidence: Math.round(conf * 100) / 100 };
}

// Flight time in seconds for each country and aircraft (base minutes x factor).
function travelTable() {
  const t = {};
  for (const [name, base] of Object.entries(TRAVEL_BASE_MIN)) {
    t[name] = { standard: Math.round(base * PLANE_FACTORS[0] * 60), airstrip: Math.round(base * PLANE_FACTORS[1] * 60), wlt: Math.round(base * PLANE_FACTORS[2] * 60), business: Math.round(base * PLANE_FACTORS[3] * 60) };
  }
  return t;
}

// Sell-through numbers for one item from its restock cycles (start = restock seen, soldout = quantity reached 0).
// sellOutSec = median time from a restock to empty; depletion = units per minute; emptiesAt = when the CURRENT stock should be gone.
function sellStats(cycles, recent, qty, now) {
  const med = (a) => { if (!a.length) return 0; const b = a.slice().sort((x, y) => x - y); return b[Math.floor(b.length / 2)]; };
  const done = cycles.filter(c => c.soldout_at > c.start_at);
  const sellOutSec = med(done.map(c => c.soldout_at - c.start_at));
  const restockQty = med(cycles.map(c => c.qty_start));
  const depletionMed = med(done.map(c => c.qty_start * 60 / (c.soldout_at - c.start_at)));
  let depletionNow = 0, from = 0;
  for (let i = 1; i < recent.length; i++) if (recent[i].qty > recent[i - 1].qty) from = i;
  const rs = recent.slice(from);
  if (rs.length >= 2) { const a = rs[0], b = rs[rs.length - 1], span = b.ts - a.ts; if (span >= 20 && a.qty > b.qty) depletionNow = (a.qty - b.qty) * 60 / span; }
  let emptiesAt = 0;
  if (qty > 0) {
    if (depletionNow > 0) emptiesAt = now + Math.round(qty * 60 / depletionNow);
    else if (depletionMed > 0) emptiesAt = now + Math.round(qty * 60 / depletionMed);
  }
  return { cycles: cycles.length, soldOuts: done.length, sellOutSec: Math.round(sellOutSec), restockQty: Math.round(restockQty), depletionMed: Math.round(depletionMed * 10) / 10, depletionNow: Math.round(depletionNow * 10) / 10, emptiesAt };
}

// Keep the shape of a step curve with at most about 4 points per bucket (first, last, min, max).
function thinSeries(points, from, to, buckets) {
  if (points.length <= buckets * 4) return points;
  const size = Math.max(1, Math.ceil((to - from) / buckets)), groups = new Map();
  for (const p of points) {
    const k = Math.floor((p[0] - from) / size), g = groups.get(k);
    if (!g) groups.set(k, { first: p, last: p, min: p, max: p });
    else { g.last = p; if (p[1] < g.min[1]) g.min = p; if (p[1] > g.max[1]) g.max = p; }
  }
  const out = [];
  for (const k of [...groups.keys()].sort((a, b) => a - b)) {
    const g = groups.get(k), pick = [g.first, g.min, g.max, g.last].sort((a, b) => a[0] - b[0]);
    for (const p of pick) if (!out.length || out[out.length - 1] !== p) out.push(p);
  }
  return out;
}

async function stockItemPayload(env, country, id, range) {
  const now = nowSeconds();
  const secs = range === "30d" ? 30 * 86400 : range === "7d" ? 7 * 86400 : 86400, since = now - secs;
  const many = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results || [];
  const base = await env.DB.prepare("SELECT qty FROM stock_hist WHERE country = ? AND item_id = ? AND ts < ? ORDER BY ts DESC LIMIT 1").bind(country, id, since).first();
  const rows = await many("SELECT ts, qty FROM stock_hist WHERE country = ? AND item_id = ? AND ts >= ? ORDER BY ts ASC LIMIT 30000", country, id, since);
  let points = rows.map(r => [Number(r.ts), Number(r.qty)]);
  if (base) points.unshift([since, Number(base.qty)]);
  points = thinSeries(points, since, now, 220);
  const restocks = (await many("SELECT seen_at, qty_before, qty_after FROM stock_events WHERE country = ? AND item_id = ? AND seen_at >= ? ORDER BY seen_at ASC LIMIT 2000", country, id, since)).map(r => [Number(r.seen_at), Number(r.qty_before), Number(r.qty_after)]);
  const soldouts = (await many("SELECT soldout_at FROM stock_cycle WHERE country = ? AND item_id = ? AND soldout_at >= ? ORDER BY soldout_at ASC LIMIT 2000", country, id, since)).map(r => Number(r.soldout_at));
  const pb = await env.DB.prepare("SELECT value FROM price_hist WHERE item_id = ? AND ts < ? ORDER BY ts DESC LIMIT 1").bind(id, since).first();
  const pr = await many("SELECT ts, value FROM price_hist WHERE item_id = ? AND ts >= ? ORDER BY ts ASC LIMIT 5000", id, since);
  let prices = pr.map(r => [Number(r.ts), Number(r.value)]);
  if (pb) prices.unshift([since, Number(pb.value)]);
  prices = thinSeries(prices, since, now, 150);
  return { ok: true, now, range: secs === 86400 ? "24h" : secs === 7 * 86400 ? "7d" : "30d", since, points, restocks, soldouts, prices };
}

async function stockPayload(env) {
  const now = nowSeconds();
  const many = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results || [];
  const snaps = await many("SELECT country, updated_at, items FROM stock_snapshot");
  const prices = new Map((await many("SELECT item_id, market_value FROM item_prices")).map(r => [Number(r.item_id), Number(r.market_value)]));
  const types = new Map((await many("SELECT item_id, type FROM item_types")).map(r => [Number(r.item_id), String(r.type)]));
  const evs = await many("SELECT country, item_id, name, prev_at, seen_at, qty_before, qty_after, cost FROM stock_events WHERE seen_at > ? ORDER BY seen_at ASC LIMIT 6000", now - 14 * 86400);
  const byKey = new Map();
  for (const e of evs) { const k = e.country + "|" + e.item_id; if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(Number(e.seen_at)); }
  const cycRows = await many("SELECT country, item_id, start_at, qty_start, end_at, soldout_at FROM stock_cycle WHERE start_at > ? ORDER BY start_at ASC LIMIT 12000", now - 7 * 86400);
  const cycBy = new Map();
  for (const c of cycRows) { const k = c.country + "|" + c.item_id; if (!cycBy.has(k)) cycBy.set(k, []); cycBy.get(k).push({ start_at: Number(c.start_at), qty_start: Number(c.qty_start), soldout_at: Number(c.soldout_at) }); }
  const recRows = await many("SELECT country, item_id, ts, qty FROM stock_hist WHERE ts > ? ORDER BY ts ASC LIMIT 20000", now - 300);
  const recBy = new Map();
  for (const r of recRows) { const k = r.country + "|" + r.item_id; if (!recBy.has(k)) recBy.set(k, []); recBy.get(k).push({ ts: Number(r.ts), qty: Number(r.qty) }); }
  const stat = (code, id, qty) => {
    const list = byKey.get(code + "|" + id) || [];
    const gaps = []; for (let i = 1; i < list.length; i++) gaps.push(list[i] - list[i - 1]);
    gaps.sort((a, b) => a - b);
    const med = gaps.length ? gaps[Math.floor(gaps.length / 2)] : 0;
    const last = list.length ? list[list.length - 1] : 0;
    return Object.assign({ restocks: list.length, lastRestockAt: last, cadenceMin: med ? Math.round(med / 60) : 0 }, stockNext(last, med, gaps, now), sellStats(cycBy.get(code + "|" + id) || [], recBy.get(code + "|" + id) || [], qty, now));
  };
  const countries = snaps.map(r => {
    let items = []; try { items = JSON.parse(r.items); } catch { items = []; }
    return { code: r.country, name: STOCK_COUNTRIES[r.country] || r.country, updatedAt: Number(r.updated_at),
      items: items.map(it => { const market = prices.get(Number(it[0])) || 0; return Object.assign({ id: it[0], name: it[1], type: types.get(Number(it[0])) || "", qty: it[2], cost: it[3], market, profit: market > 0 ? market - it[3] : null }, stat(r.country, it[0], it[2])); }) };
  }).sort((a, b) => a.name.localeCompare(b.name));
  const okAt = await env.DB.prepare("SELECT v FROM stock_state WHERE k = 'ok_at'").first();
  return {
    ok: true, now, enabled: /^https:\/\//.test(String(env.STOCK_FEED_URL || "")), lastOkAt: okAt ? Number(okAt.v) : 0, travelSec: travelTable(), countries,
    events: evs.filter(e => Number(e.seen_at) > now - 2 * 86400).reverse().slice(0, 300).map(e => ({ country: e.country, countryName: STOCK_COUNTRIES[e.country] || e.country, itemId: Number(e.item_id), name: e.name,
      prevAt: Number(e.prev_at), seenAt: Number(e.seen_at), before: Number(e.qty_before), after: Number(e.qty_after), cost: Number(e.cost) }))
  };
}

// ================= Radar insights: player reliability score + take-off clusters (beta) =================
// A player "follows the perk" when he takes off together with others: at least 3 different players leaving for the same
// country within 3 minutes of each other. Score = share of his outbound flights that were part of such a group,
// smoothed (1 virtual group flight out of 2) so that a newcomer starts at 50 and not at 0 or 100.
// Only flights whose take-off is known to within 3 minutes are used.
const INSIGHT_DAYS = 14;
const INSIGHT_GROUP_SEC = 180;
const INSIGHT_MAX_WINDOW = 180;

async function radarInsights(env) {
  const now = nowSeconds();
  const rows = (await env.DB.prepare(`
    SELECT f.player_id, f.takeoff_at, f.country, f.duration, f.win_end - f.win_start AS w, p.name, p.position, c.name AS company
    FROM radar_flights f
    LEFT JOIN radar_players p ON p.player_id = f.player_id
    LEFT JOIN radar_companies c ON c.company_id = f.company_id
    WHERE f.direction <> 'return' AND f.country IS NOT NULL AND f.takeoff_at > ?
    ORDER BY f.takeoff_at ASC LIMIT 8000
  `).bind(now - INSIGHT_DAYS * 86400).all()).results || [];

  const precise = rows.filter(r => Number(r.w) <= INSIGHT_MAX_WINDOW);
  const byCountry = new Map();
  for (const r of precise) {
    if (!byCountry.has(r.country)) byCountry.set(r.country, []);
    byCountry.get(r.country).push({ id: String(r.player_id), t: Number(r.takeoff_at), dur: Number(r.duration) || 0, name: r.name, position: r.position, company: r.company });
  }

  // flights that belong to a group: at least 2 OTHER players within 3 minutes
  const inGroup = new Set();
  const groups = [];
  for (const [country, list] of byCountry) {
    for (let i = 0; i < list.length; i++) {
      const others = new Set();
      for (let j = 0; j < list.length; j++) {
        if (j !== i && list[j].id !== list[i].id && Math.abs(list[j].t - list[i].t) <= INSIGHT_GROUP_SEC) others.add(list[j].id);
      }
      if (others.size >= 2) inGroup.add(list[i].id + "|" + list[i].t);
    }
    // clusters: consecutive take-offs within 3 minutes of the first one, at least 3 different players
    let i = 0;
    while (i < list.length) {
      const first = list[i], members = new Map(); let j = i;
      while (j < list.length && list[j].t - first.t <= INSIGHT_GROUP_SEC) { if (!members.has(list[j].id)) members.set(list[j].id, list[j]); j++; }
      if (members.size >= 3) { groups.push({ country, list: [...members.values()] }); i = j; } else i++;
    }
  }

  const per = new Map();
  for (const r of rows) {
    const id = String(r.player_id);
    const e = per.get(id) || { id, name: r.name, position: r.position, company: r.company, flights: 0, usable: 0, co: 0, last: 0, first: Number.MAX_SAFE_INTEGER };
    e.flights++; e.last = Math.max(e.last, Number(r.takeoff_at)); e.first = Math.min(e.first, Number(r.takeoff_at));
    if (Number(r.w) <= INSIGHT_MAX_WINDOW) { e.usable++; if (inGroup.has(id + "|" + Number(r.takeoff_at))) e.co++; }
    per.set(id, e);
  }
  const players = [...per.values()].map(e => {
    const score = Math.round(100 * (e.co + 1) / (e.usable + 2));
    const days = Math.max(1, Math.min(INSIGHT_DAYS, (now - e.first) / 86400));
    return { id: e.id, name: e.name, position: e.position, company: e.company, flights: e.flights, usable: e.usable, inGroups: e.co, score,
      confidence: e.usable >= 8 ? "high" : e.usable >= 3 ? "medium" : "low", perDay: Math.round(e.flights / days * 10) / 10, lastFlightAt: e.last };
  }).sort((a, b) => b.score - a.score || b.usable - a.usable || (a.name || "").localeCompare(b.name || "")).slice(0, 500);
  const score = new Map(players.map(p => [p.id, p.score]));

  const clusters = groups.map(g => {
    const members = g.list.map(m => ({ id: m.id, name: m.name, company: m.company, takeoffAt: m.t, score: score.has(m.id) ? score.get(m.id) : 50 }));
    const lands = g.list.filter(m => m.dur > 0).map(m => m.t + m.dur).sort((a, b) => a - b);
    return { country: g.country, start: Math.min(...g.list.map(m => m.t)), end: Math.max(...g.list.map(m => m.t)), members,
      landFirst: lands.length ? lands[0] : 0, landLast: lands.length ? lands[lands.length - 1] : 0 };
  }).filter(c => c.start > now - 2 * 86400).sort((a, b) => b.start - a.start).slice(0, 60);

  return { ok: true, now, days: INSIGHT_DAYS, flights: rows.length, usableFlights: precise.length, players, clusters };
}

// Parse "123, 456\n789" into a list of unique company IDs.
function radarParseIds(input) {
  const text = Array.isArray(input) ? input.join(" ") : String(input == null ? "" : input);
  const seen = new Set(), ids = [], bad = [];
  for (const tok of text.split(/[\s,;]+/).filter(Boolean)) {
    if (!/^\d{1,9}$/.test(tok) || Number(tok) <= 0) { bad.push(tok.slice(0, 20)); continue; }
    const n = Number(tok);
    if (!seen.has(n)) { seen.add(n); ids.push(n); }
  }
  return { ids, bad };
}

// ================= Closed beta (restock radar) =================
// A list of accounts managed by the admin. Admin always has access. Everything beta checks hasBeta() on the server.
async function hasBeta(env, account) {
  if (!account) return false;
  if (account.role === "admin") return true;
  try {
    const row = await env.DB.prepare(`SELECT 1 AS ok FROM beta_access WHERE account_id = ?`).bind(account.id).first();
    return !!row;
  } catch { return false; }
}

// Short, readable summary of a JSON answer: keys and types, first entries of big maps. Used by the admin diagnostic.
function shapeOf(v, depth) {
  depth = depth || 0;
  if (v === null) return "null";
  if (Array.isArray(v)) return depth > 3 ? "array(" + v.length + ")" : { __array: v.length, first: v.length ? shapeOf(v[0], depth + 1) : null };
  if (typeof v === "object") {
    if (depth > 3) return "object";
    const keys = Object.keys(v), out = {};
    const numeric = keys.length > 6 && keys.every(k => /^\d+$/.test(k));
    if (numeric) { out.__map = keys.length + " entries keyed by number"; out.example = {}; keys.slice(0, 2).forEach(k => { out.example[k] = shapeOf(v[k], depth + 1); }); return out; }
    keys.slice(0, 40).forEach(k => { out[k] = shapeOf(v[k], depth + 1); });
    if (keys.length > 40) out.__more = keys.length - 40;
    return out;
  }
  if (typeof v === "string") return "string" + (v.length ? ' "' + v.slice(0, 30) + (v.length > 30 ? "…" : "") + '"' : "");
  return typeof v + " " + String(v);
}

const DIAG_KINDS = {
  company: (id) => ["company/" + id, "profile"],
  profile: (id) => ["user/" + id, "profile"],
  personalstats: (id) => ["user/" + id, "personalstats"],
  faction: (id) => ["faction/" + id, "basic"],
  torncompanies: () => ["torn/", "companies"]
};

async function adminDiagnostic(env, kind, id) {
  const make = DIAG_KINDS[kind];
  if (!make) return { ok: false, message: "Unknown kind" };
  if (kind === "torncompanies" ? (id !== "" && !/^\d{1,3}$/.test(id)) : !/^\d{1,9}$/.test(id)) return { ok: false, message: "Enter a numeric ID" };
  const [path, sel] = make(id);
  const url = new URL("https://api.torn.com/" + path);
  url.searchParams.set("selections", sel);
  url.searchParams.set("comment", "TravelWatcher");
  url.searchParams.set("key", env.TORN_API_KEY);
  try {
    const res = await tornFetch(url.toString());
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch {}
    if (!data) return { ok: false, message: "Torn answered with something that is not JSON (HTTP " + res.status + ")" };
    if (data.error) return { ok: true, kind, status: res.status, tornError: data.error };
    if (kind === "torncompanies" && data.companies && typeof data.companies === "object") {
      // Company types: list every type with its ID, and show one type in full when its ID is given.
      const types = {};
      for (const [tid, t] of Object.entries(data.companies)) types[tid] = t && t.name ? String(t.name) : "?";
      data = id && data.companies[id] ? { types, selectedType: id, companyType: data.companies[id] } : { types };
    }
    let sample = JSON.stringify(data);
    if (sample.length > 9000) sample = sample.slice(0, 9000) + "…";
    return { ok: true, kind, status: res.status, shape: shapeOf(data), sample };
  } catch {
    return { ok: false, message: "Could not reach Torn" };
  }
}

// ================= War mode =================
// One request per faction returns every member with status, travel and last action. We read it once a minute
// for each enemy faction watched by a Premium member, keep one shared snapshot (public data), and only write
// the members whose state changed (D1 Free plan: 100k writes per day).
const WAR_MAX_FACTIONS = 2;     // distinct enemy factions read per cron run (each costs about 5 subrequests)
const PLANE_NAMES = ["Standard", "Airstrip", "WLT", "Business", "Standard+book", "Airstrip+book", "WLT+book", "Business+book"];
// plane_image_type values seen so far in the Torn API. Others are kept as they come (nothing is invented).
const PLANE_TYPE_NAMES = { airliner: "Standard", light_aircraft: "Airstrip" };

function flightFromType(country, planeType) {
  const name = PLANE_TYPE_NAMES[planeType] || null;
  const base = country ? TRAVEL_BASE_MIN[country] : 0;
  const idx = name ? PLANE_NAMES.indexOf(name) : -1;
  return { plane: name || (planeType || null), duration: base && idx >= 0 ? Math.round(base * PLANE_FACTORS[idx] * 60) : 0 };
}

// Which aircraft was used, from the window between our last check (on the ground) and this one (in the air).
// Only when exactly one aircraft fits: otherwise nothing is invented.
function inferPlane(country, untilSec, winStart, winEnd) {
  const base = country ? TRAVEL_BASE_MIN[country] : 0;
  if (!base || !(untilSec > winEnd) || !(winStart > 0)) return null;

  const found = [];
  PLANE_FACTORS.forEach((f, i) => {
    const duration = Math.round(base * f * 60);
    const takeoff = untilSec - duration;
    if (takeoff >= winStart - 5 && takeoff <= winEnd + 5) found.push({ plane: PLANE_NAMES[i], takeoff, duration });
  });

  const distinct = found.filter((v, i) => found.findIndex(w => Math.abs(w.takeoff - v.takeoff) <= 30) === i);
  if (distinct.length !== 1) return null;

  const hit = distinct[0];
  return { plane: hit.plane, takeoffAt: Math.min(winEnd, Math.max(winStart, hit.takeoff)), duration: hit.duration };
}

function warMemberFromApi(id, m) {
  const st = (m && m.status) || {};
  const la = (m && m.last_action) || {};
  const parsed = parseTravelDescription(st.description || "");
  return {
    id: String(id),
    name: typeof m.name === "string" ? m.name.slice(0, 40) : "",
    level: Math.max(0, Math.floor(Number(m.level) || 0)),
    state: typeof st.state === "string" ? st.state.slice(0, 24) : "",
    description: typeof st.description === "string" ? st.description.slice(0, 120) : "",
    until: Math.max(0, Math.floor(Number(st.until) || 0)),
    lastAction: Math.max(0, Math.floor(Number(la.timestamp) || 0)),
    country: parsed.country || null,
    direction: parsed.direction || null,
    planeType: typeof st.plane_image_type === "string" ? st.plane_image_type.slice(0, 24) : ""
  };
}

async function fetchFactionData(env, factionId) {
  try {
    const url = new URL("https://api.torn.com/faction/" + encodeURIComponent(factionId));
    url.searchParams.set("selections", "basic");
    url.searchParams.set("comment", "TravelWatcher");
    url.searchParams.set("timestamp", String(Math.floor(Date.now() / 1000))); // skip Torn's 30 s cache: allowed, and we need fresh data
    url.searchParams.set("key", env.TORN_API_KEY);
    const res = await tornFetch(url.toString());
    const data = await res.json();
    if (!res.ok || !data || typeof data !== "object") return { error: "HTTP " + res.status };
    if (data.error) return { error: "API " + (data.error.code || "?") };
    return { data };
  } catch {
    return { error: "network" };
  }
}

// Enemy faction of a faction: ranked war first, then territory / raid wars. Pure function (tested without Torn).
function pickEnemyFaction(data, myFactionId, nowSec) {
  const mine = String(myFactionId || "");
  const list = [];
  const add = (id, name, kind, start, end) => {
    const fid = String(id == null ? "" : id);
    if (!/^\d+$/.test(fid) || fid === "0" || fid === mine) return;
    if (list.some(x => x.id === fid && x.kind === kind)) return;
    list.push({ id: fid, name: typeof name === "string" ? name.slice(0, 40) : "", kind, start: Number(start) || 0, end: Number(end) || 0 });
  };

  const ranked = data && typeof data.ranked_wars === "object" && data.ranked_wars ? data.ranked_wars : {};
  for (const w of Object.values(ranked)) {
    if (!w || typeof w !== "object") continue;
    const info = w.war || {};
    for (const [fid, f] of Object.entries(w.factions || {})) add(fid, f && f.name, "ranked", info.start, info.end);
  }
  const terr = data && typeof data.territory_wars === "object" && data.territory_wars ? data.territory_wars : {};
  for (const w of Object.values(terr)) {
    if (!w || typeof w !== "object") continue;
    add(w.assaulting_faction, w.assaulting_faction_name, "territory", w.started || w.start, w.ends || w.end);
    add(w.defending_faction, w.defending_faction_name, "territory", w.started || w.start, w.ends || w.end);
  }
  const raids = data && typeof data.raid_wars === "object" && data.raid_wars ? data.raid_wars : {};
  for (const w of Object.values(raids)) {
    if (!w || typeof w !== "object") continue;
    add(w.aggressor_faction, w.aggressor_faction_name, "raid", w.start || w.started, w.end || w.ends);
    add(w.defender_faction, w.defender_faction_name, "raid", w.start || w.started, w.end || w.ends);
  }

  const active = list.filter(x => !x.end || x.end > nowSec);
  const rank = { ranked: 0, territory: 1, raid: 2 };
  active.sort((a, b) => rank[a.kind] - rank[b.kind] || b.start - a.start);
  return { best: active[0] || null, candidates: active };
}

async function detectEnemyFaction(env, tornId) {
  try {
    const url = new URL("https://api.torn.com/user/" + encodeURIComponent(tornId));
    url.searchParams.set("selections", "profile");
    url.searchParams.set("comment", "TravelWatcher");
    url.searchParams.set("key", env.TORN_API_KEY);
    const res = await tornFetch(url.toString());
    const me = await res.json();
    if (!res.ok || !me || me.error) return { ok: false, message: "Could not read your profile from Torn." };
    const myFaction = Math.floor(Number(me.faction && me.faction.faction_id) || 0);
    if (!myFaction) return { ok: false, message: "You are not in a faction." };

    const mine = await fetchFactionData(env, myFaction);
    if (!mine.data) return { ok: false, message: "Could not read your faction from Torn." };

    const pick = pickEnemyFaction(mine.data, myFaction, nowSeconds());
    if (!pick.best) return { ok: false, message: "No war found for your faction. Enter the enemy faction ID by hand.", myFaction };
    return { ok: true, myFaction, enemy: pick.best, candidates: pick.candidates.slice(0, 5) };
  } catch {
    return { ok: false, message: "Torn did not answer. Try again later." };
  }
}

async function warCollect(env) {
  const out = { ran: false, factions: 0, changed: 0, reserve: 0 };
  const now = nowSeconds();

  const wanted = await env.DB.prepare(`
    SELECT DISTINCT c.faction_id AS faction_id
    FROM war_config c
    JOIN accounts a ON a.id = c.account_id
    LEFT JOIN premium p ON p.account_id = a.id
    WHERE c.enabled = 1 AND c.faction_id > 0 AND a.active = 1
      AND (a.role = 'admin' OR COALESCE(p.premium_until, 0) > ?)
    LIMIT ?
  `).bind(now, WAR_MAX_FACTIONS).all();

  const ids = (wanted.results || []).map(r => Number(r.faction_id));
  if (!ids.length) return out;
  out.ran = true;
  out.reserve = 1 + ids.length * 5; // 1 config query + per faction: fetch, state, members, 1-2 batches

  for (const factionId of ids) {
    const got = await fetchFactionData(env, factionId);
    out.factions++;

    if (!got.data) {
      await env.DB.prepare(`
        INSERT INTO war_state (faction_id, checked_at, last_error) VALUES (?, ?, ?)
        ON CONFLICT(faction_id) DO UPDATE SET checked_at = excluded.checked_at, last_error = excluded.last_error
      `).bind(factionId, now, got.error).run();
      continue;
    }

    const members = got.data.members && typeof got.data.members === "object" ? got.data.members : {};
    const roster = Object.entries(members).map(([id, m]) => warMemberFromApi(id, m || {})).filter(m => /^\d+$/.test(m.id));

    const state = await env.DB.prepare(`SELECT checked_at, last_ok_at FROM war_state WHERE faction_id = ?`).bind(factionId).first();
    const windowStart = state && Number(state.last_ok_at) > 0 && now - Number(state.last_ok_at) <= 600 ? Number(state.last_ok_at) : 0;

    const prevRows = await env.DB.prepare(`SELECT * FROM war_members WHERE faction_id = ?`).bind(factionId).all();
    const prev = new Map((prevRows.results || []).map(r => [String(r.member_id), r]));
    const statements = [];

    for (const m of roster) {
      const p = prev.get(m.id);
      const flying = m.state === "Traveling";
      let plane = null, takeoffAt = 0, duration = 0;

      if (flying) {
        const sameFlight = p && p.state === "Traveling" && p.description === m.description;
        if (sameFlight) {
          takeoffAt = Number(p.takeoff_at) || 0;
          const f = flightFromType(m.country, m.planeType);
          plane = f.plane || p.plane || null; duration = f.duration || Number(p.duration) || 0;
        } else {
          const f = flightFromType(m.country, m.planeType);
          plane = f.plane; duration = f.duration;
          // the take-off is somewhere between our last check on the ground and this one: we keep the middle
          if (p && p.state !== "Traveling" && windowStart > 0) takeoffAt = Math.round((windowStart + now) / 2);
        }
        if (takeoffAt > 0) {
          statements.push(env.DB.prepare(`
            INSERT OR IGNORE INTO war_flights (faction_id, member_id, member_name, country, direction, plane, takeoff_at, landing_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(factionId, m.id, m.name, m.country, m.direction, plane, takeoffAt, takeoffAt + duration, now));
        }
      }

      const changed = !p || p.state !== m.state || p.description !== m.description || Number(p.until) !== m.until
        || p.name !== m.name || Number(p.level) !== m.level || Math.abs(Number(p.last_action) - m.lastAction) > 900
        || (flying && (p.plane || null) !== plane);
      if (!changed) continue;

      out.changed++;
      statements.push(env.DB.prepare(`
        INSERT INTO war_members (faction_id, member_id, name, level, state, description, until, last_action, country, direction, plane, takeoff_at, duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(faction_id, member_id) DO UPDATE SET
          name = excluded.name, level = excluded.level, state = excluded.state, description = excluded.description,
          until = excluded.until, last_action = excluded.last_action, country = excluded.country, direction = excluded.direction,
          plane = excluded.plane, takeoff_at = excluded.takeoff_at, duration = excluded.duration
      `).bind(factionId, m.id, m.name, m.level, m.state, m.description, m.until, m.lastAction, m.country, m.direction, plane, takeoffAt, duration));
    }

    // members who left the faction
    const present = new Set(roster.map(m => m.id));
    for (const id of prev.keys()) {
      if (!present.has(id)) statements.push(env.DB.prepare(`DELETE FROM war_members WHERE faction_id = ? AND member_id = ?`).bind(factionId, id));
    }

    statements.push(env.DB.prepare(`
      INSERT INTO war_state (faction_id, faction_name, checked_at, last_ok_at, last_error, member_count) VALUES (?, ?, ?, ?, NULL, ?)
      ON CONFLICT(faction_id) DO UPDATE SET faction_name = excluded.faction_name, checked_at = excluded.checked_at,
        last_ok_at = excluded.last_ok_at, last_error = NULL, member_count = excluded.member_count
    `).bind(factionId, typeof got.data.name === "string" ? got.data.name.slice(0, 40) : null, now, now, roster.length));

    for (let i = 0; i < statements.length; i += 80) await env.DB.batch(statements.slice(i, i + 80));
  }

  return out;
}

async function warPayload(env, account) {
  const now = nowSeconds();
  const cfg = await env.DB.prepare(`SELECT faction_id, enabled, updated_at FROM war_config WHERE account_id = ?`).bind(account.id).first();
  const config = { factionId: cfg ? Number(cfg.faction_id) : 0, enabled: Boolean(cfg && cfg.enabled), updatedAt: cfg ? Number(cfg.updated_at) : 0 };
  const info = await premiumInfo(env, account);
  const out = { ok: true, premium: info.active, config, state: null, members: [], now };
  if (!config.factionId) return out;

  const st = await env.DB.prepare(`SELECT faction_name, checked_at, last_ok_at, last_error, member_count FROM war_state WHERE faction_id = ?`).bind(config.factionId).first();
  if (st) out.state = { factionName: st.faction_name, checkedAt: Number(st.checked_at), lastOkAt: Number(st.last_ok_at), lastError: st.last_error, memberCount: Number(st.member_count) };

  if (info.active) {
    const rows = await env.DB.prepare(`
      SELECT member_id, name, level, state, description, until, last_action, country, direction, plane, takeoff_at, duration
      FROM war_members WHERE faction_id = ? ORDER BY name COLLATE NOCASE
    `).bind(config.factionId).all();
    out.members = (rows.results || []).map(r => ({
      id: String(r.member_id), name: r.name, level: Number(r.level), state: r.state, description: r.description,
      until: Number(r.until), lastAction: Number(r.last_action), country: r.country, direction: r.direction,
      plane: r.plane, takeoffAt: Number(r.takeoff_at), duration: Number(r.duration)
    }));
  }
  return out;
}

// Shared by the site (session) and the overlay (token). `account` = row of accounts.
async function warApi(request, env, account, path) {
  const sub = path.endsWith("/detect") ? "detect" : "config";

  if (sub === "detect") {
    if (request.method !== "POST") return json({ ok: false, message: "Method not allowed" }, 405);
    const bucket = "wardetect:" + account.id;
    const wait = await lockedSeconds(env, bucket);
    if (wait > 0) return tooManyAttempts(wait);
    await registerFailure(env, bucket, 6, 600, 600);
    const found = await detectEnemyFaction(env, account.torn_user_id);
    return json(found, found.ok ? 200 : 404);
  }

  if (request.method === "GET") return json(await warPayload(env, account));

  if (request.method === "PUT") {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const cur = await env.DB.prepare(`SELECT faction_id, enabled FROM war_config WHERE account_id = ?`).bind(account.id).first();
    let factionId = cur ? Number(cur.faction_id) : 0;
    let enabled = cur ? Number(cur.enabled) : 0;

    if (body.factionId !== undefined) {
      const n = Number(body.factionId);
      if (!Number.isInteger(n) || n < 0 || n > 99999999) return json({ ok: false, message: "Invalid faction ID." }, 400);
      factionId = n;
    }
    if (body.enabled !== undefined) enabled = body.enabled === true ? 1 : 0;
    if (enabled && !factionId) enabled = 0;

    await env.DB.prepare(`
      INSERT INTO war_config (account_id, faction_id, enabled, updated_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(account_id) DO UPDATE SET faction_id = excluded.faction_id, enabled = excluded.enabled, updated_at = excluded.updated_at
    `).bind(account.id, factionId, enabled, nowSeconds()).run();

    return json(await warPayload(env, account));
  }

  return json({ ok: false, message: "Method not allowed" }, 405);
}

async function ownerXanaxCheck(env) {
  const out = { ran: false, credited: 0, pending: 0 };

  if (!vaultAvailable(env)) return out;

  const nowSec = nowSeconds();
  const row = await env.DB.prepare(`
    SELECT k.enc AS enc, k.status AS status, s.since_ts AS since_ts, s.last_run_at AS last_run_at
    FROM owner_key k LEFT JOIN owner_log_state s ON s.id = 1
    WHERE k.id = 1
  `).first();

  if (!row || row.status !== "valid") return out;
  if (row.last_run_at && nowSec - row.last_run_at < XANAX_CHECK_EVERY) return out;

  out.ran = true;
  const since = row.since_ts || nowSec;

  // claimed before the request, so two overlapping runs never read the log twice
  await env.DB.prepare(`
    INSERT INTO owner_log_state (id, since_ts, last_run_at, checks_total) VALUES (1, ?, ?, 1)
    ON CONFLICT(id) DO UPDATE SET last_run_at = excluded.last_run_at, checks_total = owner_log_state.checks_total + 1
  `).bind(since, nowSec).run();

  const fail = async (text) => {
    await env.DB.prepare(`UPDATE owner_log_state SET last_error = ? WHERE id = 1`).bind(text).run();
    return out;
  };

  let apiKey;
  try {
    apiKey = await decryptUserKey(env, "owner", row.enc);
  } catch {
    return await fail("Stored key cannot be decrypted");
  }

  const res = await tornKeyRequest("user/", "log", apiKey);

  if (!res.data) return await fail("Torn unreachable");

  if (res.data.error) {
    const code = Number(res.data.error.code);

    if ([2, 13, 16, 18].includes(code)) {
      await env.DB.prepare(`UPDATE owner_key SET status = 'invalid', last_error = ?, last_check_at = ? WHERE id = 1`)
        .bind("Torn error " + code, nowSec).run();
    }

    return await fail("Torn error " + code);
  }

  const raw = res.data.log;
  const list = Array.isArray(raw) ? raw : Object.entries(raw || {}).map(([id, v]) => (v && typeof v === "object" ? { id, ...v } : null)).filter(Boolean);

  const candidates = list
    .filter(e => /^[A-Za-z0-9_-]{6,40}$/.test(String(e.id)) && Number(e.timestamp) >= since && xanaxQty(e) > 0)
    .sort((a, b) => Number(a.timestamp) - Number(b.timestamp))
    .slice(0, 20);

  if (candidates.length) {
    const refs = candidates.map(e => "torn-log:" + e.id);
    const known = await env.DB.prepare(`
      SELECT ref FROM premium_credits WHERE ref IN (SELECT value FROM json_each(?))
      UNION
      SELECT ref FROM premium_pending WHERE ref IN (SELECT value FROM json_each(?))
    `).bind(JSON.stringify(refs), JSON.stringify(refs)).all();
    const seen = new Set((known.results || []).map(r => r.ref));

    const fresh = candidates.filter(e => !seen.has("torn-log:" + e.id));

    if (fresh.length) {
      const senders = [...new Set(fresh.map(e => String(e.data.sender)))].filter(v => /^\d{1,12}$/.test(v));
      const found = await env.DB.prepare(`
        SELECT id, torn_user_id FROM accounts WHERE active = 1 AND torn_user_id IN (SELECT value FROM json_each(?))
      `).bind(JSON.stringify(senders)).all();
      const byTorn = new Map((found.results || []).map(a => [String(a.torn_user_id), a.id]));

      const rateCache = new Map();
      let liveLookups = 0;

      for (const e of fresh) {
        const qty = xanaxQty(e);
        const ref = "torn-log:" + e.id;
        const accountId = byTorn.get(String(e.data.sender));
        let hoursEach = XANAX_HOURS_EACH;

        if (accountId) {
          if (!rateCache.has(accountId)) {
            let aff;
            if (liveLookups < 3) { liveLookups++; aff = await affiliationFor(env, accountId, String(e.data.sender), 0); }
            else aff = (await storedAffiliation(env, accountId)) || { sameFaction: false, sameCompany: false };
            rateCache.set(accountId, hoursPerXanaxFor(aff));
          }
          hoursEach = rateCache.get(accountId);
        }

        if (accountId && qty * hoursEach <= XANAX_MAX_HOURS) {
          await premiumCredit(env, accountId, qty * hoursEach, "xanax", ref, "Xanax x" + qty + " (" + PREMIUM_KEYWORD + ")" + (hoursEach === XANAX_HOURS_BONUS ? " faction/company rate" : ""), null);
          out.credited++;
        } else {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO premium_pending (ref, sender_id, qty, entry_ts, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(ref, String(e.data.sender).slice(0, 12), qty, Number(e.timestamp), accountId ? "quantity above the automatic limit" : "sender has no account", nowSec).run();
          out.pending++;
        }
      }
    }
  }

  await env.DB.prepare(`
    UPDATE owner_log_state SET last_ok_at = ?, last_error = NULL,
      credited_total = credited_total + ?, pending_total = pending_total + ?
    WHERE id = 1
  `).bind(nowSec, out.credited, out.pending).run();

  return out;
}

const TS_WORKER = {
  async fetch(request, env, ctx) {
    try {
      return await TS_WORKER.handle(request, env);
    } finally {
      if (USAGE_BUF.size) {
        const p = flushUsage(env);
        if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p); else await p;
      }
    }
  },

  async handle(request, env) {
    rememberOwnerKeys(env);
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (!env.DB || !env.TORN_API_KEY || !env.APP_SECRET) {
      return json({
        ok: false,
        message: "Server configuration incomplete"
      }, 500);
    }

    await ensureSchema(env);

    // État du service
    if (request.method === "GET" && path === "/health") {
      return json({
        ok: true,
        service: "TornScope",
        version: "3.26.0",
        collector: await collectorHeartbeat(env)
      });
    }

    // Initialisation unique de l'administrateur.
    // Cette route est désactivée si ADMIN_SETUP_TOKEN a été supprimé.
    if (request.method === "POST" && path === "/setup-admin") {
      if (!env.ADMIN_SETUP_TOKEN) {
        return json({
          ok: false,
          message: "Setup disabled"
        }, 503);
      }

      const suppliedToken =
        request.headers.get("X-Admin-Setup-Token") || "";

      if (!timingSafeEqual(suppliedToken, env.ADMIN_SETUP_TOKEN)) {
        return json({
          ok: false,
          message: "Access denied"
        }, 403);
      }

      try {
        const body = await request.json();
        const password = body.password;

        if (
          typeof password !== "string" ||
          password.length < 12 ||
          password.length > 128
        ) {
          return json({
            ok: false,
            message: "The password must be between 12 and 128 characters"
          }, 400);
        }

        const existingAdmin = await env.DB.prepare(`
          SELECT id FROM accounts
          WHERE role = 'admin'
          LIMIT 1
        `).first();

        if (existingAdmin) {
          return json({
            ok: false,
            message: "The administrator account already exists"
          }, 409);
        }

        const identity = await verifyTornIdentity(
          env,
          ADMIN_TORN_ID,
          ADMIN_USERNAME
        );

        if (!identity) {
          return json({
            ok: false,
            message: "Torn identity not verified"
          }, 403);
        }

        const passwordHash = await hashPassword(password);

        await env.DB.prepare(`
          INSERT INTO accounts
            (username, password_hash, torn_user_id, role, active)
          VALUES (?, ?, ?, 'admin', 1)
        `).bind(
          ADMIN_USERNAME,
          passwordHash,
          ADMIN_TORN_ID
        ).run();

        await ensureAppUser(
          env,
          ADMIN_TORN_ID,
          ADMIN_USERNAME
        );

        return json({
          ok: true,
          message: "Administrator account created"
        }, 201);
      } catch (error) {
        console.error("Erreur setup-admin:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Setup failed"
        }, 500);
      }
    }

    // Inscription avec invitation
    if (request.method === "POST" && path === "/register") {
      try {
        const body = await request.json();

        const username =
          typeof body.username === "string"
            ? body.username.trim()
            : "";

        const tornUserId =
          typeof body.tornUserId === "string" ||
          typeof body.tornUserId === "number"
            ? String(body.tornUserId).trim()
            : "";

        const password =
          typeof body.password === "string"
            ? body.password
            : "";

        const invitationCode =
          typeof body.invitationCode === "string"
            ? body.invitationCode.trim()
            : "";

        if (
          !/^[a-zA-Z0-9_-]{3,32}$/.test(username) ||
          !/^\d{1,12}$/.test(tornUserId) ||
          password.length < 12 ||
          password.length > 128 ||
          !/^[a-f0-9]{64}$/.test(invitationCode)
        ) {
          return json({
            ok: false,
            message: "Invalid details. Your username must be your exact Torn name, the Torn ID must be numbers only, the password at least 12 characters and the invitation code complete."
          }, 400);
        }

        const invitationHash = await sha256(invitationCode);

        const invitation = await env.DB.prepare(`
          SELECT id
          FROM invitations
          WHERE code_hash = ?
            AND used_by IS NULL
            AND revoked = 0
            AND expires_at > unixepoch()
        `).bind(invitationHash).first();

        if (!invitation) {
          return json({
            ok: false,
            message: "Invitation invalid, expired or already used"
          }, 403);
        }

        const identity = await verifyTornIdentity(
          env,
          tornUserId,
          username
        );

        if (!identity) {
          return json({
            ok: false,
            message: "Torn identity not verified"
          }, 403);
        }

        const passwordHash = await hashPassword(password);

        // Prévenir les comptes en double.
        const duplicate = await env.DB.prepare(`
          SELECT id
          FROM accounts
          WHERE username = ? COLLATE NOCASE
             OR torn_user_id = ?
          LIMIT 1
        `).bind(username, tornUserId).first();

        if (duplicate) {
          return json({
            ok: false,
            message: "This username or Torn ID is already in use"
          }, 409);
        }

        // Réserver l'invitation, créer le compte, puis la marquer utilisée.
        const result = await env.DB.batch([
          env.DB.prepare(`
            UPDATE invitations
            SET revoked = 2
            WHERE id = ?
              AND used_by IS NULL
              AND revoked = 0
              AND expires_at > unixepoch()
          `).bind(invitation.id),

          env.DB.prepare(`
            INSERT INTO accounts
              (username, password_hash, torn_user_id, role, active)
            SELECT ?, ?, ?, 'user', 1
            WHERE EXISTS (
              SELECT 1 FROM invitations
              WHERE id = ?
                AND revoked = 2
                AND used_by IS NULL
            )
          `).bind(
            username,
            passwordHash,
            tornUserId,
            invitation.id
          ),

          env.DB.prepare(`
            UPDATE invitations
            SET used_by = (
              SELECT id FROM accounts
              WHERE username = ? COLLATE NOCASE
                AND torn_user_id = ?
            ),
            used_at = unixepoch(),
            revoked = 0
            WHERE id = ?
              AND revoked = 2
              AND used_by IS NULL
              AND EXISTS (
                SELECT 1 FROM accounts
                WHERE username = ? COLLATE NOCASE
                  AND torn_user_id = ?
              )
          `).bind(
            username,
            tornUserId,
            invitation.id,
            username,
            tornUserId
          )
        ]);

        if (
          result[0].meta.changes !== 1 ||
          result[1].meta.changes !== 1 ||
          result[2].meta.changes !== 1
        ) {
          return json({
            ok: false,
            message: "Invitation invalid or already used"
          }, 409);
        }

        // Créer aussi l'utilisateur applicatif pour les clés étrangères.
        await ensureAppUser(env, tornUserId, username);

        // Faction / company bonus (best effort: a Torn hiccup must never block a registration).
        try {
          const created = await env.DB.prepare(`SELECT id FROM accounts WHERE torn_user_id = ?`).bind(tornUserId).first();
          if (created) await refreshAffiliation(env, created.id, tornUserId);
        } catch (error) {
          console.error("Affiliation check error:", error?.stack || String(error));
        }

        return json({
          ok: true,
          message: "Account created successfully",
          user: {
            username,
            tornUserId,
            role: "user"
          }
        }, 201);
      } catch (error) {
        console.error("Erreur inscription:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Registration failed. Check the details and try again."
        }, 400);
      }
    }

    // Log in with a Torn API key (no password). The account is created the first time.
    // The key is used once to read the public profile (who owns it), then discarded: it is never stored.
    if (request.method === "POST" && path === "/login-key") {
      try {
        const ip = clientIp(request);
        const failBucket = "keylogin-ip:" + ip;
        const wait = await lockedSeconds(env, failBucket);
        if (wait > 0) return tooManyAttempts(wait);

        let body = {};
        try { body = await request.json(); } catch { body = {}; }
        const apiKey = typeof body.key === "string" ? body.key.trim() : "";
        const remember = body.remember === true;   // "Keep me logged in": 30 days, otherwise 12 hours
        const agreed = body.agree === true;        // the data and API key use was accepted

        if (!KEY_FORMAT.test(apiKey)) {
          await registerFailure(env, failBucket, 10, 900, 900);
          return json({ ok: false, message: "Paste your Torn API key (16 letters and digits)." }, 400);
        }

        const profile = await tornKeyRequest("user/", "basic", apiKey);
        if (!profile.data) {
          return json({ ok: false, message: "Could not reach the Torn API. Try again later." }, 502);
        }
        if (profile.data.error) {
          await registerFailure(env, failBucket, 10, 900, 900);
          return json({ ok: false, message: tornKeyErrorMessage(profile.data.error.code) }, 400);
        }

        const tornId = String(profile.data.player_id || "");
        const tornName = typeof profile.data.name === "string" ? profile.data.name.trim() : "";
        if (!/^\d{1,12}$/.test(tornId) || !tornName) {
          return json({ ok: false, message: "Torn did not return a valid player for this key." }, 400);
        }

        // Safety: refuse keys that can read private data. A Public key is all we need.
        const info = await tornKeyRequest("key/", "info", apiKey);
        const level = info.data && !info.data.error && typeof info.data.access_type === "string" ? info.data.access_type : "";
        if (/limited|full/i.test(level)) {
          return json({ ok: false, message: "For your safety, use a key with Public access only (Torn: Settings → API Keys → create a Public key). Higher access is not needed and is refused." }, 400);
        }

        let account = await env.DB.prepare(`
          SELECT id, username, password_hash, torn_user_id, role, active
          FROM accounts WHERE torn_user_id = ?
        `).bind(tornId).first();
        let created = false;

        if (account) {
          if (account.active !== 1) {
            return json({ ok: false, message: "This account is disabled." }, 403);
          }
          if (!String(account.password_hash).startsWith("key-login")) {
            // Accounts protected by a password (the administrator, invited members) never accept a key login.
            return json({ ok: false, message: "This account uses a username and password. Log in with them instead." }, 409);
          }
        } else {
          if (!agreed) {
            return json({ ok: false, message: "Please accept the data and API key use to create your account." }, 400);
          }
          const newBucket = "keynew-ip:" + ip;
          const waitNew = await lockedSeconds(env, newBucket);
          if (waitNew > 0) return tooManyAttempts(waitNew);

          let username = tornName.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 32);
          if (username.length < 3) username = ("tc" + tornId).slice(0, 32);
          const taken = await env.DB.prepare(`SELECT id FROM accounts WHERE username = ? COLLATE NOCASE`).bind(username).first();
          if (taken) username = (username.slice(0, 20) + "-" + tornId).slice(0, 32);

          await env.DB.prepare(`
            INSERT INTO accounts (username, password_hash, torn_user_id, role, active)
            VALUES (?, 'key-login', ?, 'user', 1)
          `).bind(username, tornId).run();

          await ensureAppUser(env, tornId, tornName);
          created = true;
          await registerFailure(env, newBucket, 5, 3600, 3600); // at most 5 new accounts per address and hour

          account = await env.DB.prepare(`
            SELECT id, username, password_hash, torn_user_id, role, active
            FROM accounts WHERE torn_user_id = ?
          `).bind(tornId).first();

          try { await refreshAffiliation(env, account.id, tornId); }
          catch (error) { console.error("Affiliation check error:", error?.stack || String(error)); }
        }

        await clearFailures(env, failBucket);

        const token = randomToken();
        const tokenHash = await sha256(token);
        const lifetime = remember ? 30 * 24 * 60 * 60 : 12 * 60 * 60;
        const expiresAt = Math.floor(Date.now() / 1000) + lifetime;
        await env.DB.prepare(`
          INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)
        `).bind(tokenHash, account.id, expiresAt).run();

        return json({
          ok: true,
          created,
          user: { username: account.username, tornUserId: account.torn_user_id, role: account.role }
        }, 200, { "Set-Cookie": sessionCookie(token, lifetime) });
      } catch (error) {
        console.error("Key login error:", error?.stack || String(error));
        return json({ ok: false, message: "Login failed" }, 500);
      }
    }

    // Connexion
    if (request.method === "POST" && path === "/login") {
      try {
        const body = await request.json();

        const username =
          typeof body.username === "string"
            ? body.username.trim()
            : "";

        const password =
          typeof body.password === "string"
            ? body.password
            : "";

        if (
          !username ||
          !password ||
          username.length > 64 ||
          password.length > 128
        ) {
          return json({
            ok: false,
            message: "Identifiants invalides"
          }, 400);
        }

        // Limites : 5 essais ratés par compte et par adresse IP, 30 par adresse IP (15 minutes).
        // Le compartiment "compte + IP" évite qu'un inconnu bloque ton compte depuis une autre adresse.
        const ip = clientIp(request);
        const userBucket = "login:" + username.toLowerCase() + "|" + ip;
        const ipBucket = "login-ip:" + ip;

        const waitSeconds = Math.max(
          await lockedSeconds(env, userBucket),
          await lockedSeconds(env, ipBucket)
        );

        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }

        const account = await env.DB.prepare(`
          SELECT id, username, password_hash, torn_user_id, role
          FROM accounts
          WHERE username = ? COLLATE NOCASE
            AND active = 1
        `).bind(username).first();

        // Même travail de calcul que le compte existe ou non (évite de deviner les noms d'utilisateur au temps de réponse).
        const passwordOk = account
          ? await verifyPassword(password, account.password_hash)
          : (await hashPassword(password, "salt-factice-pour-le-temps"), false);

        if (!account || !passwordOk) {
          await registerFailure(env, userBucket, 5, 900, 900);
          await registerFailure(env, ipBucket, 30, 900, 900);

          return json({
            ok: false,
            message: "Incorrect username or password"
          }, 401);
        }

        await clearFailures(env, userBucket);

        const token = randomToken();
        const tokenHash = await sha256(token);

        const expiresAt =
          Math.floor(Date.now() / 1000) + SESSION_SECONDS;

        await env.DB.prepare(`
          INSERT INTO sessions (token_hash, account_id, expires_at)
          VALUES (?, ?, ?)
        `).bind(tokenHash, account.id, expiresAt).run();

        return json({
          ok: true,
          user: {
            username: account.username,
            tornUserId: account.torn_user_id,
            role: account.role
          }
        }, 200, {
          "Set-Cookie": sessionCookie(token)
        });
      } catch (error) {
        console.error("Erreur connexion:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Login failed"
        }, 500);
      }
    }

    // Session actuelle
    if (request.method === "GET" && path === "/me") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      return json({
        ok: true,
        user: {
          username: account.username,
          tornUserId: account.torn_user_id,
          role: account.role,
          premium: await premiumInfo(env, account),
          beta: await hasBeta(env, account),
          keyLogin: !!(await env.DB.prepare(`SELECT 1 AS k FROM accounts WHERE id = ? AND password_hash LIKE 'key-login%'`).bind(account.id).first())
        }
      });
    }

    // Déconnexion
    if (request.method === "POST" && path === "/logout") {
      const token = cookieValue(request, "ttw_session");

      if (token && /^[a-f0-9]{64}$/.test(token)) {
        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE token_hash = ?
        `).bind(await sha256(token)).run();
      }

      return json({
        ok: true,
        message: "Logged out"
      }, 200, {
        "Set-Cookie": sessionCookie("", 0)
      });
    }

    // Changer son propre mot de passe (session requise)
    if (request.method === "POST" && path === "/account/password") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const body = await request.json();

        const currentPassword =
          typeof body.currentPassword === "string"
            ? body.currentPassword
            : "";

        const newPassword =
          typeof body.newPassword === "string"
            ? body.newPassword
            : "";

        if (!currentPassword || currentPassword.length > MAX_PASSWORD_LENGTH) {
          return json({
            ok: false,
            message: "Current password required"
          }, 400);
        }

        if (!validPassword(newPassword)) {
          return json({
            ok: false,
            message: "The new password must be between 12 and 128 characters"
          }, 400);
        }

        const bucket = "pwchange:" + account.id;
        const waitSeconds = await lockedSeconds(env, bucket);

        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }

        const row = await env.DB.prepare(`
          SELECT password_hash FROM accounts WHERE id = ?
        `).bind(account.id).first();

        if (!row || !(await verifyPassword(currentPassword, row.password_hash))) {
          await registerFailure(env, bucket, 5, 900, 900);

          return json({
            ok: false,
            message: "Current password is incorrect"
          }, 403);
        }

        if (currentPassword === newPassword) {
          return json({
            ok: false,
            message: "The new password must be different from the old one"
          }, 400);
        }

        const newHash = await hashPassword(newPassword);
        const currentSessionHash = await sha256(cookieValue(request, "ttw_session"));

        // Les autres sessions sont fermées ; celle-ci reste ouverte.
        await env.DB.batch([
          env.DB.prepare(`
            UPDATE accounts SET password_hash = ? WHERE id = ?
          `).bind(newHash, account.id),

          env.DB.prepare(`
            DELETE FROM sessions
            WHERE account_id = ? AND token_hash <> ?
          `).bind(account.id, currentSessionHash)
        ]);

        await clearFailures(env, bucket);

        return json({
          ok: true,
          message: "Password changed. Your other sessions were closed."
        });
      } catch (error) {
        console.error("Erreur changement mot de passe:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not change the password"
        }, 500);
      }
    }

    // Administrateur : créer un code de réinitialisation à usage unique pour un utilisateur
    if (request.method === "POST" && path === "/admin/reset-codes") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      if (!requireAdmin(account)) {
        return json({
          ok: false,
          message: "Access denied"
        }, 403);
      }

      try {
        const body = await request.json();

        const username =
          typeof body.username === "string"
            ? body.username.trim()
            : "";

        if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
          return json({
            ok: false,
            message: "Invalid username"
          }, 400);
        }

        const target = await env.DB.prepare(`
          SELECT id, username
          FROM accounts
          WHERE username = ? COLLATE NOCASE
            AND active = 1
        `).bind(username).first();

        if (!target) {
          return json({
            ok: false,
            message: "Account not found"
          }, 404);
        }

        const code = randomToken(32);
        const codeHash = await sha256(code);
        const expiresAt = nowSeconds() + RESET_CODE_SECONDS;

        // Un seul code actif par compte : les anciens codes inutilisés sont supprimés.
        await env.DB.batch([
          env.DB.prepare(`
            DELETE FROM password_resets
            WHERE account_id = ? AND used_at IS NULL
          `).bind(target.id),

          env.DB.prepare(`
            INSERT INTO password_resets (code_hash, account_id, created_by, expires_at)
            VALUES (?, ?, ?, ?)
          `).bind(codeHash, target.id, account.id, expiresAt)
        ]);

        return json({
          ok: true,
          username: target.username,
          resetCode: code,
          expiresAt
        }, 201);
      } catch (error) {
        console.error("Erreur création code reset:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not create the code"
        }, 500);
      }
    }

    // Utilisateur : choisir un nouveau mot de passe avec un code de réinitialisation
    if (request.method === "POST" && path === "/reset") {
      try {
        const ipBucket = "reset-ip:" + clientIp(request);
        const waitSeconds = await lockedSeconds(env, ipBucket);

        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }

        const body = await request.json();

        const code =
          typeof body.code === "string"
            ? body.code.trim().toLowerCase()
            : "";

        const password =
          typeof body.password === "string"
            ? body.password
            : "";

        if (!validPassword(password)) {
          return json({
            ok: false,
            message: "The password must be between 12 and 128 characters"
          }, 400);
        }

        const invalid = async () => {
          await registerFailure(env, ipBucket, 10, 900, 3600);

          return json({
            ok: false,
            message: "Invalid or expired code"
          }, 403);
        };

        if (!/^[a-f0-9]{64}$/.test(code)) {
          return await invalid();
        }

        const codeHash = await sha256(code);

        // Le code est "consommé" en une seule opération : deux requêtes simultanées ne peuvent pas l'utiliser deux fois.
        const claim = await env.DB.prepare(`
          UPDATE password_resets
          SET used_at = unixepoch()
          WHERE code_hash = ?
            AND used_at IS NULL
            AND expires_at > unixepoch()
        `).bind(codeHash).run();

        if (claim.meta.changes !== 1) {
          return await invalid();
        }

        const reset = await env.DB.prepare(`
          SELECT account_id FROM password_resets WHERE code_hash = ?
        `).bind(codeHash).first();

        const newHash = await hashPassword(password);

        await env.DB.batch([
          env.DB.prepare(`
            UPDATE accounts SET password_hash = ?
            WHERE id = ? AND active = 1
          `).bind(newHash, reset.account_id),

          env.DB.prepare(`
            DELETE FROM sessions WHERE account_id = ?
          `).bind(reset.account_id)
        ]);

        await clearFailures(env, ipBucket);

        return json({
          ok: true,
          message: "Password changed. You can now log in."
        });
      } catch (error) {
        console.error("Erreur reset mot de passe:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not change the password"
        }, 500);
      }
    }

    // Récupération du propriétaire (désactivée tant que le secret ADMIN_SETUP_TOKEN n'existe pas)
    if (request.method === "POST" && path === "/admin/recover") {
      if (!env.ADMIN_SETUP_TOKEN) {
        return json({
          ok: false,
          message: "Recovery disabled"
        }, 503);
      }

      const bucket = "recover-ip:" + clientIp(request);
      const waitSeconds = await lockedSeconds(env, bucket);

      if (waitSeconds > 0) {
        return tooManyAttempts(waitSeconds);
      }

      const supplied = request.headers.get("X-Admin-Setup-Token") || "";

      if (
        !timingSafeEqual(
          await sha256(supplied),
          await sha256(env.ADMIN_SETUP_TOKEN)
        )
      ) {
        await registerFailure(env, bucket, 5, 900, 3600);

        return json({
          ok: false,
          message: "Access denied"
        }, 403);
      }

      try {
        const body = await request.json();

        const username =
          typeof body.username === "string" && body.username.trim()
            ? body.username.trim()
            : ADMIN_USERNAME;

        if (!validPassword(body.password)) {
          return json({
            ok: false,
            message: "The password must be between 12 and 128 characters"
          }, 400);
        }

        const target = await env.DB.prepare(`
          SELECT id, username
          FROM accounts
          WHERE username = ? COLLATE NOCASE
            AND active = 1
        `).bind(username).first();

        if (!target) {
          return json({
            ok: false,
            message: "Account not found"
          }, 404);
        }

        const newHash = await hashPassword(body.password);

        await env.DB.batch([
          env.DB.prepare(`
            UPDATE accounts SET password_hash = ? WHERE id = ?
          `).bind(newHash, target.id),

          env.DB.prepare(`
            DELETE FROM sessions WHERE account_id = ?
          `).bind(target.id)
        ]);

        await clearFailures(env, bucket);

        return json({
          ok: true,
          message:
            "Password reset for " + target.username +
            ". Now delete the ADMIN_SETUP_TOKEN secret in Cloudflare."
        });
      } catch (error) {
        console.error("Erreur récupération propriétaire:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Recovery failed"
        }, 500);
      }
    }

    // Pages de récupération
    if (request.method === "GET" && path === "/recover") {
      if (!env.ADMIN_SETUP_TOKEN) {
        return json({
          ok: false,
          message: "Unknown route"
        }, 404);
      }

      return authPage(
        "Recovery",
        "Account recovery",
        "Reserved for the project owner. This page only exists while the ADMIN_SETUP_TOKEN secret is present in Cloudflare.",
        RECOVER_FORM,
        RECOVER_SCRIPT
      );
    }

    if (request.method === "GET" && path === "/terms") {
      return new Response(TERMS_PAGE, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" } });
    }

    if (request.method === "GET" && (path === "/join" || path === "/register")) {
      return authPage(
        "Create your account",
        "Create your account",
        "You need an invitation from the administrator. Your name and ID are checked with Torn; we never ask for your Torn password.",
        REGISTER_FORM,
        REGISTER_SCRIPT
      );
    }

    if (request.method === "GET" && path === "/reset") {
      return authPage(
        "New password",
        "New password",
        "Enter the code you received from the administrator, then choose your new password.",
        RESET_FORM,
        RESET_SCRIPT
      );
    }

    // ---- Événements de vol envoyés par le script (jeton overlay)
    if (request.method === "POST" && path === "/overlay/events") {
      const overlayAccount = await getOverlayAccount(request, env);

      if (!overlayAccount) {
        return json({
          ok: false,
          message: "Overlay token invalid or revoked"
        }, 401);
      }

      try {
        const body = await request.json();
        const list = Array.isArray(body.events) ? body.events : null;

        if (!list || list.length === 0 || list.length > MAX_EVENTS_PER_REQUEST) {
          return json({
            ok: false,
            message: "Expected between 1 and " + MAX_EVENTS_PER_REQUEST + " events"
          }, 400);
        }

        // Les événements ne sont acceptés que pour les cibles de CE compte.
        const owned = await env.DB.prepare(`
          SELECT target_torn_id FROM targets WHERE user_id = ?
        `).bind(overlayAccount.user_id).all();

        const ownedIds = new Set((owned.results || []).map(r => String(r.target_torn_id)));
        const nowSec = nowSeconds();

        let accepted = 0;
        let duplicates = 0;
        let rejected = 0;

        for (const raw of list) {
          const clientId = cleanText(raw && raw.clientId, 80);
          const targetId = cleanText(raw && String(raw.targetId ?? ""), 12);
          const type = cleanText(raw && raw.type, 20);
          const observedAt = cleanInt(raw && raw.observedAt, 1500000000, nowSec + 300);

          if (
            !clientId ||
            !/^\d{1,12}$/.test(targetId) ||
            !EVENT_TYPES.includes(type) ||
            observedAt === null ||
            !ownedIds.has(targetId)
          ) {
            rejected++;
            continue;
          }

          const description = cleanText(raw.description, 80);
          const parsed = parseTravelDescription(description);
          const stateTo = KNOWN_STATES.includes(raw.stateTo) ? raw.stateTo : null;
          const stateFrom = KNOWN_STATES.includes(raw.stateFrom) ? raw.stateFrom : null;
          const quality = raw.quality === "in_flight" ? "in_flight" : raw.quality === "inferred" ? "inferred" : "observed";
          const landingSource = raw.landingSource === "api" ? "api" : raw.landingSource === "estimate" ? "estimate" : null;
          const landingAt = cleanInt(raw.landingAt, 1500000000, nowSec + 3 * 24 * 3600);

          // Pour une arrivée, la durée vient du dernier départ réellement observé.
          let durationMin = null;

          if (type === "arrival") {
            const lastDeparture = await env.DB.prepare(`
              SELECT observed_at FROM travel_events
              WHERE user_id = ? AND target_torn_id = ?
                AND event_type = 'departure' AND quality IN ('observed', 'inferred')
                AND observed_at <= ?
              ORDER BY observed_at DESC
              LIMIT 1
            `).bind(overlayAccount.user_id, targetId, observedAt).first();

            if (lastDeparture) {
              const minutes = Math.round((observedAt - lastDeparture.observed_at) / 60);
              durationMin = minutes >= 0 && minutes <= 12 * 60 ? minutes : null;
            }
          }

          if (type === "departure") {
            // One take-off cannot happen twice within 4 minutes: merge instead of adding a second row.
            const near = await env.DB.prepare(`
              SELECT id, quality FROM travel_events
              WHERE user_id = ? AND target_torn_id = ? AND event_type = 'departure'
                AND ABS(observed_at - ?) <= 240
              ORDER BY id LIMIT 1
            `).bind(overlayAccount.user_id, targetId, observedAt).first();

            if (near) {
              await env.DB.prepare(`
                UPDATE travel_events SET
                  landing_at = COALESCE(landing_at, ?),
                  landing_source = COALESCE(landing_source, ?),
                  country = COALESCE(country, ?),
                  direction = COALESCE(direction, ?),
                  description = COALESCE(description, ?),
                  plane = COALESCE(plane, ?)
                WHERE id = ?
              `).bind(landingAt, landingSource, parsed.country, parsed.direction, description || null,
                      cleanText(raw.plane, 30) || null, near.id).run();
              duplicates++;
              continue;
            }
          }

          const result = await env.DB.prepare(`
            INSERT OR IGNORE INTO travel_events (
              user_id, client_id, target_torn_id, target_name, event_type,
              state_from, state_to, description, country, direction,
              observed_at, landing_at, landing_source, duration_min, quality, plane
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            overlayAccount.user_id, clientId, targetId,
            cleanText(raw.targetName, 40) || null, type,
            stateFrom, stateTo, description || null,
            parsed.country, parsed.direction,
            observedAt, landingAt, landingSource, durationMin, quality,
            cleanText(raw.plane, 30) || null
          ).run();

          if (result.meta.changes > 0) accepted++;
          else duplicates++;
        }

        // Rétention : on garde EVENT_RETENTION_DAYS jours.
        if (Math.random() < 0.02) {
          await env.DB.prepare(`
            DELETE FROM travel_events WHERE user_id = ? AND observed_at < ?
          `).bind(overlayAccount.user_id, nowSec - EVENT_RETENTION_DAYS * 86400).run();
        }

        return json({ ok: true, accepted, duplicates, rejected });
      } catch (error) {
        console.error("Erreur enregistrement événements:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not save the events"
        }, 500);
      }
    }

    // ---- Lecture des événements (session, filtres combinables)
    if (request.method === "GET" && path === "/api/events") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      try {
        const appUser = await ensureAppUser(env, account.torn_user_id, account.username);

        if (!appUser) {
          return json({ ok: false, message: "User not found" }, 500);
        }

        const params = url.searchParams;
        const where = ["1 = 1"];
        const binds = [];

        const target = params.get("target");
        if (target && /^\d{1,12}$/.test(target)) {
          where.push("target_torn_id = ?");
          binds.push(target);
        }

        const type = params.get("type");
        if (type && EVENT_TYPES.includes(type)) {
          where.push("event_type = ?");
          binds.push(type);
        }

        const country = cleanText(params.get("country") || "", 40);
        if (country) {
          where.push("country = ?");
          binds.push(country);
        }

        const from = cleanInt(params.get("from"), 0, 4102444800);
        if (from !== null) {
          where.push("observed_at >= ?");
          binds.push(from);
        }

        const to = cleanInt(params.get("to"), 0, 4102444800);
        if (to !== null) {
          where.push("observed_at <= ?");
          binds.push(to);
        }

        const limit = cleanInt(params.get("limit"), 1, 1000) || 100;
        const offset = cleanInt(params.get("offset"), 0, 100000) || 0;
        const order = params.get("order") === "asc" ? "ASC" : "DESC";

        // Two sources, merged: events pushed by MY userscript, and events observed by the server for the
        // players I watch. If both saw the same thing (same player, same type, same flight) only the
        // script's copy is kept: its clock is more precise (5 s polling instead of 1 min).
        await backfillCountries(env);
        const premiumFlag = (await premiumInfo(env, account)).active ? 1 : 0;
        const unionSql = `(
          SELECT id, target_torn_id, target_name, event_type, state_from, state_to, description,
                 country, direction, observed_at, NULL AS observed_after, landing_at, landing_source,
                 duration_min, quality, plane, 'script' AS source
          FROM travel_events WHERE user_id = ?
          UNION ALL
          SELECT e.id, e.target_torn_id, w.name, e.event_type, e.state_from, e.state_to, e.description,
                 e.country, e.direction, e.observed_at, e.observed_after, e.landing_at, e.landing_source,
                 e.duration_min, e.quality, NULL, 'server'
          FROM target_events e
          LEFT JOIN watch_targets w ON w.target_torn_id = e.target_torn_id
          WHERE e.target_torn_id IN (SELECT target_torn_id FROM targets WHERE user_id = ?)
            AND ? = 1
            AND NOT EXISTS (
              SELECT 1 FROM travel_events x
              WHERE x.user_id = ? AND x.target_torn_id = e.target_torn_id
                AND x.event_type = e.event_type
                AND (
                  ABS(x.observed_at - e.observed_at) <= 240
                  OR (e.event_type = 'departure' AND x.landing_at IS NOT NULL AND e.landing_at IS NOT NULL
                      AND ABS(x.landing_at - e.landing_at) <= 180)
                  OR (e.event_type = 'departure' AND e.quality = 'in_flight'
                      AND x.observed_at <= e.observed_at AND x.observed_at >= e.observed_at - 43200
                      AND COALESCE(x.landing_at, x.observed_at + 43200) >= e.observed_at - 180)
                )
            )
        ) ev`;
        const unionBinds = [appUser.id, appUser.id, premiumFlag, appUser.id];

        const totalRow = await env.DB.prepare(`
          SELECT COUNT(*) AS total FROM ${unionSql} WHERE ${where.join(" AND ")}
        `).bind(...unionBinds, ...binds).first();

        const rows = await env.DB.prepare(`
          SELECT id,
                 target_torn_id AS targetId,
                 target_name AS targetName,
                 event_type AS type,
                 state_from AS stateFrom,
                 state_to AS stateTo,
                 description,
                 country, direction,
                 observed_at AS observedAt,
                 observed_after AS observedAfter,
                 landing_at AS landingAt,
                 landing_source AS landingSource,
                 duration_min AS durationMin,
                 quality, plane, source
          FROM ${unionSql}
          WHERE ${where.join(" AND ")}
          ORDER BY observed_at ${order}, id ${order}
          LIMIT ? OFFSET ?
        `).bind(...unionBinds, ...binds, limit, offset).all();

        return json({
          ok: true,
          total: totalRow ? totalRow.total : 0,
          events: rows.results || []
        });
      } catch (error) {
        console.error("Erreur lecture événements:", error?.stack || String(error));

        return json({ ok: false, message: "Could not load the history" }, 500);
      }
    }

    // ---- Préférences (thème, alertes)
    if (path === "/api/prefs" && (request.method === "GET" || request.method === "PUT")) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      try {
        if (request.method === "GET") {
          const row = await env.DB.prepare(`
            SELECT data FROM user_prefs WHERE account_id = ?
          `).bind(account.id).first();

          let prefs = null;
          try { prefs = row ? validPrefs(JSON.parse(row.data)) : null; } catch { prefs = null; }

          return json({ ok: true, prefs });
        }

        const body = await request.json();
        const prefs = validPrefs(body.prefs);

        if (!prefs) {
          return json({ ok: false, message: "Invalid preferences" }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO user_prefs (account_id, data, updated_at)
          VALUES (?, ?, unixepoch())
          ON CONFLICT(account_id) DO UPDATE SET
            data = excluded.data,
            updated_at = excluded.updated_at
        `).bind(account.id, JSON.stringify(prefs)).run();

        return json({ ok: true });
      } catch (error) {
        console.error("Erreur préférences:", error?.stack || String(error));

        return json({ ok: false, message: "Could not save the preferences" }, 500);
      }
    }

    // ---- Premium: my status
    if (request.method === "GET" && path === "/api/premium") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      const history = await env.DB.prepare(`
        SELECT created_at AS createdAt, hours, source FROM premium_credits
        WHERE account_id = ? ORDER BY created_at DESC, id DESC LIMIT 30
      `).bind(account.id).all();

      const affil = account.role === "admin" ? null : await affiliationFor(env, account.id, account.torn_user_id, AFFIL_MAX_AGE);
      const rateHours = hoursPerXanaxFor(affil);

      return json({
        ok: true,
        premium: await premiumInfo(env, account),
        payment: {
          keyword: PREMIUM_KEYWORD,
          payeeId: ADMIN_TORN_ID,
          payeeName: ADMIN_USERNAME,
          hoursPerXanax: rateHours,
          daysPerXanax: rateHours / 24,
          bonus: affiliationBonus(affil),
          maxXanax: Math.floor(XANAX_MAX_HOURS / rateHours),
          yourTornId: account.torn_user_id,
          profileUrl: "https://www.torn.com/profiles.php?XID=" + ADMIN_TORN_ID
        },
        history: history.results || []
      });
    }

    // ---- Premium administration (manual credit / revoke, history)
    if (path === "/admin/premium" && (request.method === "GET" || request.method === "POST")) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      if (!requireAdmin(account)) {
        return json({ ok: false, message: "Access denied" }, 403);
      }

      try {
        if (request.method === "GET") {
          const accounts = await env.DB.prepare(`
            SELECT a.id AS id, a.username AS username, a.role AS role, p.premium_until AS premiumUntil
            FROM accounts a LEFT JOIN premium p ON p.account_id = a.id
            ORDER BY a.username COLLATE NOCASE
          `).all();

          const credits = await env.DB.prepare(`
            SELECT c.created_at AS createdAt, a.username AS username, c.hours AS hours, c.source AS source, c.note AS note
            FROM premium_credits c JOIN accounts a ON a.id = c.account_id
            ORDER BY c.created_at DESC, c.id DESC LIMIT 30
          `).all();

          const pending = await env.DB.prepare(`
            SELECT ref, sender_id AS senderId, qty, entry_ts AS entryTs, reason
            FROM premium_pending WHERE status = 'open' ORDER BY entry_ts DESC LIMIT 50
          `).all();

          return json({ ok: true, now: nowSeconds(), accounts: accounts.results || [], credits: credits.results || [], pending: pending.results || [] });
        }

        let body;
        try { body = await request.json(); } catch { body = {}; }

        const username = typeof body.username === "string" ? body.username.trim() : "";

        if (typeof body.pendingRef === "string") {
          const p = await env.DB.prepare(`SELECT ref, qty, status FROM premium_pending WHERE ref = ?`).bind(body.pendingRef).first();

          if (!p || p.status !== "open") {
            return json({ ok: false, message: "This entry is not pending." }, 404);
          }

          if (body.dismiss === true) {
            await env.DB.prepare(`UPDATE premium_pending SET status = 'dismissed', resolved_at = ? WHERE ref = ?`).bind(nowSeconds(), p.ref).run();
            return json({ ok: true, message: "Entry dismissed." });
          }

          const who = username
            ? await env.DB.prepare(`SELECT id, username FROM accounts WHERE username = ? COLLATE NOCASE`).bind(username).first()
            : null;

          if (!who) {
            return json({ ok: false, message: "Unknown username" }, 404);
          }

          const rate = hoursPerXanaxFor(await storedAffiliation(env, who.id));
          const hoursDue = Math.min(XANAX_MAX_HOURS, p.qty * rate);
          await premiumCredit(env, who.id, hoursDue, "xanax", p.ref, "Xanax x" + p.qty + " (resolved manually)", account.id);
          await env.DB.prepare(`UPDATE premium_pending SET status = 'resolved', resolved_at = ?, resolved_account = ? WHERE ref = ?`).bind(nowSeconds(), who.id, p.ref).run();

          return json({ ok: true, message: hoursDue + " h credited to " + who.username + "." });
        }

        const target = username
          ? await env.DB.prepare(`SELECT id, username FROM accounts WHERE username = ? COLLATE NOCASE`).bind(username).first()
          : null;

        if (!target) {
          return json({ ok: false, message: "Unknown username" }, 404);
        }

        if (body.revoke === true) {
          await env.DB.batch([
            env.DB.prepare(`DELETE FROM premium WHERE account_id = ?`).bind(target.id),
            env.DB.prepare(`
              INSERT INTO premium_credits (account_id, hours, source, ref, note, created_by, created_at)
              VALUES (?, 0, 'revoke', ?, 'Premium revoked', ?, ?)
            `).bind(target.id, "revoke:" + randomToken(8), account.id, nowSeconds())
          ]);

          return json({ ok: true, message: "Premium revoked for " + target.username + "." });
        }

        const hours = Number(body.hours);

        if (!Number.isInteger(hours) || hours < 1 || hours > 8760) {
          return json({ ok: false, message: "Hours must be a whole number between 1 and 8760." }, 400);
        }

        await premiumCredit(env, target.id, hours, "manual", "manual:" + randomToken(8), cleanText(body.note, 80), account.id);

        const row = await env.DB.prepare(`SELECT premium_until FROM premium WHERE account_id = ?`).bind(target.id).first();

        return json({
          ok: true,
          message: hours + " h credited to " + target.username + ".",
          premiumUntil: row ? row.premium_until : null
        });
      } catch (error) {
        console.error("Premium admin error:", error?.name || "error");

        return json({ ok: false, message: "Could not update premium" }, 500);
      }
    }

    // ---- Owner key (Full access, read-only use: Torn log). Encrypted, never returned, admin only.
    if (path === "/admin/owner-key" && (request.method === "GET" || request.method === "PUT" || request.method === "DELETE")) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      if (!requireAdmin(account)) {
        return json({ ok: false, message: "Access denied" }, 403);
      }

      const available = vaultAvailable(env);

      try {
        if (request.method === "GET") {
          const row = await env.DB.prepare(`
            SELECT torn_id, torn_name, access_type, status, last_check_at, last_error, updated_at FROM owner_key WHERE id = 1
          `).first();

          const det = await env.DB.prepare(`
            SELECT since_ts, last_run_at, last_ok_at, last_error, checks_total, credited_total, pending_total FROM owner_log_state WHERE id = 1
          `).first();

          return json({
            ok: true,
            available,
            key: row ? {
              status: row.status, tornId: row.torn_id, tornName: row.torn_name, accessType: row.access_type,
              lastCheckAt: row.last_check_at, lastError: row.last_error, savedAt: row.updated_at
            } : null,
            detector: det ? {
              sinceTs: det.since_ts, lastRunAt: det.last_run_at, lastOkAt: det.last_ok_at, lastError: det.last_error,
              checks: det.checks_total, credited: det.credited_total, pending: det.pending_total
            } : null
          });
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(`DELETE FROM owner_key WHERE id = 1`).run();
          return json({ ok: true, message: "The owner key was deleted from the server." });
        }

        if (!available) {
          return json({ ok: false, message: "Key storage is not configured on the server yet." }, 503);
        }

        const bucket = "ownerkey:" + account.id;
        const waitSeconds = await lockedSeconds(env, bucket);

        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }

        let body;
        try { body = await request.json(); } catch { body = {}; }

        const apiKey = typeof body.key === "string" ? body.key.trim() : "";

        if (!KEY_FORMAT.test(apiKey)) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({ ok: false, message: "A Torn API key is 16 letters and digits." }, 400);
        }

        const profile = await tornKeyRequest("user/", "profile", apiKey);

        if (!profile.data) {
          return json({ ok: false, message: "Could not reach the Torn API. Try again later." }, 502);
        }

        if (profile.data.error) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({ ok: false, message: tornKeyErrorMessage(profile.data.error.code) }, 400);
        }

        if (String(profile.data.player_id) !== String(account.torn_user_id)) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({ ok: false, message: "This key does not belong to your linked Torn account." }, 403);
        }

        // The whole point of this key: it must be able to read the log.
        const log = await tornKeyRequest("user/", "log", apiKey);

        if (!log.data) {
          return json({ ok: false, message: "Could not reach the Torn API. Try again later." }, 502);
        }

        if (log.data.error) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({
            ok: false,
            message: Number(log.data.error.code) === 16
              ? "This key cannot read your log: Torn requires Full Access for it."
              : tornKeyErrorMessage(log.data.error.code)
          }, 400);
        }

        let accessType = null;
        const info = await tornKeyRequest("key/", "info", apiKey);
        if (info.data && !info.data.error && typeof info.data.access_type === "string") {
          accessType = cleanText(info.data.access_type, 24);
        }

        const stored = await encryptUserKey(env, "owner", apiKey);
        const now = nowSeconds();

        await env.DB.prepare(`
          INSERT INTO owner_key (id, enc, torn_id, torn_name, access_type, status, last_check_at, last_error, updated_at)
          VALUES (1, ?, ?, ?, ?, 'valid', ?, NULL, ?)
          ON CONFLICT(id) DO UPDATE SET
            enc = excluded.enc, torn_id = excluded.torn_id, torn_name = excluded.torn_name,
            access_type = excluded.access_type, status = 'valid', last_check_at = excluded.last_check_at,
            last_error = NULL, updated_at = excluded.updated_at
        `).bind(stored, String(profile.data.player_id), cleanText(profile.data.name, 40), accessType, now, now).run();

        await clearFailures(env, bucket);

        return json({
          ok: true,
          message: "Owner key verified (log readable) and saved.",
          key: { status: "valid", tornId: String(profile.data.player_id), tornName: cleanText(profile.data.name, 40), accessType, lastCheckAt: now, lastError: null, savedAt: now }
        });
      } catch (error) {
        console.error("Owner key error:", error?.name || "error");

        return json({ ok: false, message: "Could not process the key" }, 500);
      }
    }

    // ---- Owner log viewer: raw entries of MY OWN Torn log, filtered by a text (default "xanax"), admin only.
    // Used to see the exact format Torn returns before writing the automatic detector.
    if (request.method === "GET" && path === "/admin/owner-log") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      if (!requireAdmin(account)) {
        return json({ ok: false, message: "Access denied" }, 403);
      }

      try {
        if (!vaultAvailable(env)) {
          return json({ ok: false, message: "Key storage is not configured on the server yet." }, 503);
        }

        const row = await env.DB.prepare(`SELECT enc FROM owner_key WHERE id = 1`).first();

        if (!row) {
          return json({ ok: false, message: "No owner key stored yet." }, 404);
        }

        let apiKey;
        try {
          apiKey = await decryptUserKey(env, "owner", row.enc);
        } catch {
          return json({ ok: false, message: "The stored key cannot be decrypted (was the secret changed?). Save the key again." }, 500);
        }

        const waitSeconds = await lockedSeconds(env, "ownerlog:" + account.id);
        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }
        // at most 1 fetch every 10 s
        await registerFailure(env, "ownerlog:" + account.id, 1, 10, 10);

        const res = await tornKeyRequest("user/", "log", apiKey);

        if (!res.data) {
          return json({ ok: false, message: "Could not reach the Torn API. Try again later." }, 502);
        }

        if (res.data.error) {
          const code = Number(res.data.error.code);
          await env.DB.prepare(`UPDATE owner_key SET last_check_at = ?, last_error = ?, status = ? WHERE id = 1`)
            .bind(nowSeconds(), "Torn error " + code, [2, 13, 16, 18].includes(code) ? "invalid" : "valid").run();

          return json({ ok: false, message: tornKeyErrorMessage(code) }, 400);
        }

        const raw = res.data.log;
        const list = Array.isArray(raw) ? raw : Object.entries(raw || {}).map(([id, v]) => (v && typeof v === "object" ? { id, ...v } : { id, value: v }));

        const filter = cleanText(new URL(request.url).searchParams.get("filter") || "", 40).toLowerCase();
        const matched = filter ? list.filter(e => JSON.stringify(e).toLowerCase().includes(filter)) : list;

        matched.sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));

        await env.DB.prepare(`UPDATE owner_key SET last_check_at = ?, last_error = NULL, status = 'valid' WHERE id = 1`).bind(nowSeconds()).run();

        return json({
          ok: true,
          fetched: list.length,
          matched: matched.length,
          topLevelKeys: Object.keys(res.data).slice(0, 10),
          entries: matched.slice(0, 15)
        });
      } catch (error) {
        console.error("Owner log error:", error?.name || "error");

        return json({ ok: false, message: "Could not read the log" }, 500);
      }
    }

    // ---- Personal Torn API key for server-side collection (never returned, never logged)
    if (path === "/api/key" && (request.method === "GET" || request.method === "PUT" || request.method === "DELETE")) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      const available = vaultAvailable(env);

      try {
        if (request.method === "GET") {
          const row = await env.DB.prepare(`
            SELECT torn_id, torn_name, access_type, status, last_check_at, last_ok_at, last_error, created_at, updated_at
            FROM user_keys WHERE account_id = ?
          `).bind(account.id).first();

          return json({
            ok: true,
            available,
            key: row ? {
              status: row.status,
              tornId: row.torn_id,
              tornName: row.torn_name,
              accessType: row.access_type,
              lastCheckAt: row.last_check_at,
              lastOkAt: row.last_ok_at,
              lastError: row.last_error,
              savedAt: row.updated_at
            } : null
          });
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(`DELETE FROM user_keys WHERE account_id = ?`).bind(account.id).run();
          return json({ ok: true, message: "Your key was deleted from the server." });
        }

        if (!available) {
          return json({ ok: false, message: "Key storage is not configured on the server yet." }, 503);
        }

        if (!account.torn_user_id) {
          return json({ ok: false, message: "Your account has no linked Torn ID." }, 400);
        }

        const bucket = "keyset:" + account.id;
        const waitSeconds = await lockedSeconds(env, bucket);

        if (waitSeconds > 0) {
          return tooManyAttempts(waitSeconds);
        }

        let body;
        try { body = await request.json(); } catch { body = {}; }

        const apiKey = typeof body.key === "string" ? body.key.trim() : "";

        // Wrong keys sent to Torn can get the server's IP banned: check the format first and limit the attempts.
        if (!KEY_FORMAT.test(apiKey)) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({ ok: false, message: "A Torn API key is 16 letters and digits." }, 400);
        }

        const profile = await tornKeyRequest("user/", "profile", apiKey);
        const pdata = profile.data;

        if (!pdata) {
          return json({ ok: false, message: "Could not reach the Torn API. Try again later." }, 502);
        }

        if (pdata.error) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({ ok: false, message: tornKeyErrorMessage(pdata.error.code) }, 400);
        }

        // Identity proof: a key can only read its own owner's profile without an ID.
        if (String(pdata.player_id) !== String(account.torn_user_id)) {
          await registerFailure(env, bucket, 6, 600, 900);
          return json({
            ok: false,
            message: "This key does not belong to the Torn account linked to your profile (ID " + account.torn_user_id + ")."
          }, 403);
        }

        // Access level: informational only (best effort).
        let accessType = null;
        const info = await tornKeyRequest("key/", "info", apiKey);
        if (info.data && !info.data.error && typeof info.data.access_type === "string") {
          accessType = cleanText(info.data.access_type, 24);
        }

        const stored = await encryptUserKey(env, account.id, apiKey);
        const now = nowSeconds();

        await env.DB.prepare(`
          INSERT INTO user_keys (account_id, enc, torn_id, torn_name, access_type, status, last_check_at, last_ok_at, last_error, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, 'valid', ?, ?, NULL, ?, ?)
          ON CONFLICT(account_id) DO UPDATE SET
            enc = excluded.enc,
            torn_id = excluded.torn_id,
            torn_name = excluded.torn_name,
            access_type = excluded.access_type,
            status = 'valid',
            last_check_at = excluded.last_check_at,
            last_ok_at = excluded.last_ok_at,
            last_error = NULL,
            updated_at = excluded.updated_at
        `).bind(
          account.id, stored, String(pdata.player_id), cleanText(pdata.name, 40), accessType, now, now, now, now
        ).run();

        await clearFailures(env, bucket);

        const warning = accessType && accessType.toLowerCase() !== "public"
          ? "This key has more access than needed (" + accessType + "). A Public key is enough: consider replacing it."
          : null;

        return json({
          ok: true,
          message: "Key verified and saved.",
          warning,
          key: {
            status: "valid",
            tornId: String(pdata.player_id),
            tornName: cleanText(pdata.name, 40),
            accessType,
            lastCheckAt: now,
            lastOkAt: now,
            lastError: null,
            savedAt: now
          }
        });
      } catch (error) {
        console.error("Key route error:", error?.name || "error");

        return json({ ok: false, message: "Could not process the key" }, 500);
      }
    }

    // ---- Fermer les autres sessions
    if (request.method === "POST" && path === "/account/sessions/revoke-others") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      const current = await sha256(cookieValue(request, "ttw_session"));

      await env.DB.prepare(`
        DELETE FROM sessions WHERE account_id = ? AND token_hash <> ?
      `).bind(account.id, current).run();

      return json({ ok: true, message: "Your other sessions were closed." });
    }

    // ---- Administration : lecture seule, sans donnée sensible
    if (request.method === "GET" && (path === "/admin/users" || path === "/admin/status")) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      if (!requireAdmin(account)) {
        return json({ ok: false, message: "Access denied" }, 403);
      }

      try {
        if (path === "/admin/users") {
          const result = await env.DB.prepare(`
            SELECT a.id AS id,
                   a.username AS username,
                   a.torn_user_id AS tornUserId,
                   a.role AS role,
                   a.active AS active,
                   (SELECT COUNT(*) FROM targets t JOIN users u ON u.id = t.user_id
                      WHERE u.torn_user_id = a.torn_user_id) AS targets,
                   (SELECT COUNT(*) FROM travel_events e JOIN users u ON u.id = e.user_id
                      WHERE u.torn_user_id = a.torn_user_id) AS events,
                   (SELECT COUNT(*) FROM overlay_tokens o JOIN users u ON u.id = o.user_id
                      WHERE u.torn_user_id = a.torn_user_id AND o.revoked_at IS NULL) AS tokens,
                   (SELECT k.status FROM user_keys k WHERE k.account_id = a.id) AS keyStatus,
                   (SELECT 1 FROM beta_access b WHERE b.account_id = a.id) AS beta
            FROM accounts a
            ORDER BY a.id
          `).all();

          return json({ ok: true, users: result.results || [] });
        }

        const one = async (sql) => (await env.DB.prepare(sql).first()) || {};

        const accounts = await one("SELECT COUNT(*) AS n, SUM(active = 1) AS a FROM accounts");
        const targets = await one("SELECT COUNT(*) AS n FROM targets");
        const events = await one("SELECT (SELECT COUNT(*) FROM travel_events) + (SELECT COUNT(*) FROM target_events) AS n, MAX((SELECT MAX(observed_at) FROM travel_events), (SELECT MAX(observed_at) FROM target_events)) AS last");
        const tokens = await one("SELECT COUNT(*) AS n FROM overlay_tokens WHERE revoked_at IS NULL");
        const sessions = await one("SELECT COUNT(*) AS n FROM sessions WHERE expires_at > unixepoch()");

        return json({
          ok: true,
          status: {
            accounts: accounts.n || 0,
            activeAccounts: accounts.a || 0,
            targets: targets.n || 0,
            events: events.n || 0,
            lastEventAt: events.last || null,
            activeOverlayTokens: tokens.n || 0,
            sessions: sessions.n || 0
          }
        });
      } catch (error) {
        console.error("Erreur admin:", error?.stack || String(error));

        return json({ ok: false, message: "Could not load the data" }, 500);
      }
    }

    // ---- Restock radar page data (closed beta)
    if (path === "/api/radar" && request.method === "GET") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!(await hasBeta(env, account))) return json({ ok: false, message: "Unknown route" }, 404);
      try { return json(await radarPayload(env)); }
      catch (error) { console.error("Radar page error:", error?.stack || String(error)); return json({ ok: false, message: "Radar failed" }, 500); }
    }

    if (path === "/api/radar/stock" && request.method === "GET") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!(await hasBeta(env, account))) return json({ ok: false, message: "Unknown route" }, 404);
      try { return json(await stockPayload(env)); }
      catch (error) { console.error("Stock payload error:", error?.stack || String(error)); return json({ ok: false, message: "Stock failed" }, 500); }
    }

    if (path === "/api/radar/stock/item" && request.method === "GET") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!(await hasBeta(env, account))) return json({ ok: false, message: "Unknown route" }, 404);
      const country = String(url.searchParams.get("country") || ""), id = Number(url.searchParams.get("id"));
      if (!STOCK_COUNTRIES[country] || !Number.isInteger(id) || id <= 0) return json({ ok: false, message: "Bad request" }, 400);
      try { return json(await stockItemPayload(env, country, id, String(url.searchParams.get("range") || "24h"))); }
      catch (error) { console.error("Stock item error:", error?.stack || String(error)); return json({ ok: false, message: "Stock failed" }, 500); }
    }

    if (path === "/api/radar/insights" && request.method === "GET") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!(await hasBeta(env, account))) return json({ ok: false, message: "Unknown route" }, 404);
      try { return json(await radarInsights(env)); }
      catch (error) { console.error("Radar insights error:", error?.stack || String(error)); return json({ ok: false, message: "Radar failed" }, 500); }
    }

    if (path === "/admin/api-usage") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!requireAdmin(account)) return json({ ok: false, message: "Access denied" }, 403);
      if (request.method !== "GET") return json({ ok: false, message: "Method not allowed" }, 405);
      return json({ ok: true, usage: await apiUsageReport(env) });
    }

    // ---- Restock radar: companies, import and manual read (admin only)
    if (path === "/admin/radar" || path === "/admin/radar/run") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!requireAdmin(account)) return json({ ok: false, message: "Access denied" }, 403);
      try {
        if (path === "/admin/radar/run") {
          if (request.method !== "POST") return json({ ok: false, message: "Method not allowed" }, 405);
          const now = nowSeconds();
          const res = await radarCollect(env, 0, 20);   // the ones that are due, up to 20
          return json({ ok: true, result: res, at: now });
        }
        if (request.method === "GET") {
          const now = nowSeconds();
          const companies = await env.DB.prepare(`
            SELECT company_id AS id, name, company_type AS type, rating, employees, active, last_read_at AS lastReadAt, next_read_at AS nextReadAt, last_error AS lastError
            FROM radar_companies ORDER BY company_id
          `).all();
          const one = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).first()) || {};
          const pl = await one(`SELECT COUNT(*) AS n, SUM(state = 'Traveling') AS flying FROM radar_players`);
          const fl = await one(`SELECT COUNT(*) AS n, SUM(created_at > ?) AS last24h, SUM(landed_seen_at > 0) AS landed FROM radar_flights`, now - 86400);
          return json({ ok: true, now, companies: companies.results || [], stats: { players: pl.n || 0, flying: pl.flying || 0, flights: fl.n || 0, flights24h: fl.last24h || 0, landed: fl.landed || 0 } });
        }
        if (request.method === "POST") {
          let body = {}; try { body = await request.json(); } catch {}
          if (body.remove !== undefined) {
            const id = Math.floor(Number(body.remove));
            if (!(id > 0)) return json({ ok: false, message: "Invalid company" }, 400);
            await env.DB.batch([
              env.DB.prepare(`DELETE FROM radar_players WHERE company_id = ?`).bind(id),
              env.DB.prepare(`DELETE FROM radar_companies WHERE company_id = ?`).bind(id)
            ]);
            return json({ ok: true, removed: id });
          }
          const { ids, bad } = radarParseIds(body.ids);
          if (!ids.length) return json({ ok: false, message: bad.length ? "No valid ID (digits only)." : "Paste at least one company ID." }, 400);
          if (ids.length > 500) return json({ ok: false, message: "500 companies at most per import." }, 400);
          const now = nowSeconds();
          const existing = new Set(((await env.DB.prepare(`SELECT company_id FROM radar_companies WHERE company_id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all()).results || []).map(r => Number(r.company_id)));
          const statements = ids.map(id => existing.has(id)
            ? env.DB.prepare(`UPDATE radar_companies SET active = 1, fail_count = 0, last_error = NULL, next_read_at = 0 WHERE company_id = ?`).bind(id)
            : env.DB.prepare(`INSERT INTO radar_companies (company_id, added_at, next_read_at) VALUES (?, ?, 0)`).bind(id, now));
          for (let i = 0; i < statements.length; i += 80) await env.DB.batch(statements.slice(i, i + 80));
          return json({ ok: true, added: ids.filter(i => !existing.has(i)).length, existing: ids.filter(i => existing.has(i)).length, invalid: bad.length });
        }
        return json({ ok: false, message: "Method not allowed" }, 405);
      } catch (error) {
        console.error("Radar admin error:", error?.stack || String(error));
        return json({ ok: false, message: "Radar admin failed" }, 500);
      }
    }

    // ---- Closed beta list + diagnostic (admin only)
    if (path === "/admin/beta" || path === "/admin/diagnostic") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      if (!requireAdmin(account)) return json({ ok: false, message: "Access denied" }, 403);
      try {
        if (path === "/admin/diagnostic") {
          if (request.method !== "GET") return json({ ok: false, message: "Method not allowed" }, 405);
          const kind = String(url.searchParams.get("kind") || "");
          const id = String(url.searchParams.get("id") || "").trim();
          const out = await adminDiagnostic(env, kind, id);
          return json(out, out.ok ? 200 : 400);
        }
        if (request.method === "GET") {
          const rows = await env.DB.prepare(`
            SELECT a.id AS id, a.username AS username, a.torn_user_id AS tornUserId, a.role AS role, b.granted_at AS grantedAt
            FROM beta_access b JOIN accounts a ON a.id = b.account_id ORDER BY a.username
          `).all();
          return json({ ok: true, members: rows.results || [] });
        }
        if (request.method === "POST") {
          let body = {}; try { body = await request.json(); } catch {}
          const accountId = Math.floor(Number(body.accountId));
          if (!(accountId > 0)) return json({ ok: false, message: "Invalid account" }, 400);
          const target = await env.DB.prepare(`SELECT id, role FROM accounts WHERE id = ?`).bind(accountId).first();
          if (!target) return json({ ok: false, message: "Account not found" }, 404);
          if (body.enabled === false) {
            await env.DB.prepare(`DELETE FROM beta_access WHERE account_id = ?`).bind(accountId).run();
          } else {
            await env.DB.prepare(`INSERT INTO beta_access (account_id, granted_at) VALUES (?, ?) ON CONFLICT(account_id) DO NOTHING`).bind(accountId, nowSeconds()).run();
          }
          return json({ ok: true, enabled: body.enabled !== false });
        }
        return json({ ok: false, message: "Method not allowed" }, 405);
      } catch (error) {
        console.error("Beta admin error:", error?.stack || String(error));
        return json({ ok: false, message: "Beta admin failed" }, 500);
      }
    }

    // ---- Collector indicators (admin) and manual run
    if (path === "/admin/collector" || path === "/admin/collector/run") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({ ok: false, message: "Login required" }, 401);
      }

      if (!requireAdmin(account)) {
        return json({ ok: false, message: "Access denied" }, 403);
      }

      try {
        if (request.method === "POST" && path === "/admin/collector/run") {
          const summary = await collect(env, "manual");
          return json({ ok: true, summary });
        }

        if (request.method !== "GET") {
          return json({ ok: false, message: "Method not allowed" }, 405);
        }

        const now = nowSeconds();
        const one = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).first()) || {};
        const many = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).all()).results || [];

        const state = await one(`SELECT * FROM collector_state WHERE id = 1`);
        const watched = await one(`
          SELECT COUNT(*) AS n, MAX(last_polled_at) AS lastPoll,
                 SUM(CASE WHEN next_poll_at <= ? THEN 1 ELSE 0 END) AS due
          FROM watch_targets w
          WHERE EXISTS (SELECT 1 FROM targets t WHERE t.target_torn_id = w.target_torn_id AND ${PREMIUM_TARGET_SQL})
        `, now, now);
        const subscriptions = await one(`SELECT COUNT(*) AS n FROM targets`);
        const events = await one(`
          SELECT COUNT(*) AS total, MAX(observed_at) AS last,
                 SUM(CASE WHEN observed_at > ? THEN 1 ELSE 0 END) AS last24h
          FROM target_events
        `, now - 86400);
        const runs = await many(`
          SELECT started_at AS startedAt, duration_ms AS durationMs, trigger, due, polled, ok, errors, events, deferred, note
          FROM collector_runs ORDER BY started_at DESC, id DESC LIMIT 30
        `);
        const targets = await many(`
          SELECT w.target_torn_id AS tornId, w.name AS name, w.state AS state, w.description AS description,
                 w.last_polled_at AS lastPolledAt, w.next_poll_at AS nextPollAt, w.polls AS polls,
                 w.error_count AS errorCount, w.last_error AS lastError, w.last_error_at AS lastErrorAt
          FROM watch_targets w
          WHERE EXISTS (SELECT 1 FROM targets t WHERE t.target_torn_id = w.target_torn_id AND ${PREMIUM_TARGET_SQL})
          ORDER BY COALESCE(w.last_polled_at, 0) ASC
          LIMIT 100
        `, now);

        return json({
          ok: true,
          now,
          keyConfigured: Boolean(collectorKey(env)),
          budgetPerRun: collectorBudget(env),
          state: {
            lastRunAt: state.last_run_at || null,
            lastRunTrigger: state.last_run_trigger || null,
            lastSuccessAt: state.last_success_at || null,
            lastPollAt: state.last_poll_at || null,
            runsTotal: state.runs_total || 0,
            pollsTotal: state.polls_total || 0,
            errorsTotal: state.errors_total || 0,
            eventsTotal: state.events_total || 0,
            haltedUntil: state.halted_until || 0,
            haltedReason: state.halted_reason || null,
            lastError: state.last_error || null,
            lastErrorAt: state.last_error_at || null
          },
          watchedTargets: watched.n || 0,
          subscriptions: subscriptions.n || 0,
          dueNow: watched.due || 0,
          lastObservationAt: watched.lastPoll || null,
          events: { total: events.total || 0, last24h: events.last24h || 0, lastAt: events.last || null },
          runs,
          targets
        });
      } catch (error) {
        console.error("Collector admin error:", error?.stack || String(error));

        return json({ ok: false, message: "Could not load the collector status" }, 500);
      }
    }

    // Créer une invitation administrateur
    if (
      request.method === "POST" &&
      path === "/admin/invitations"
    ) {
      try {
        const account = await getAccount(request, env);

        if (!account) {
          return json({
            ok: false,
            message: "Login required"
          }, 401);
        }

        if (!requireAdmin(account)) {
          return json({
            ok: false,
            message: "Access denied"
          }, 403);
        }

        const invitation = await createInvitation(
          env,
          account.id,
          7
        );

        return json({
          ok: true,
          invitationCode: invitation.code,
          expiresAt: invitation.expiresAt
        }, 201);
      } catch (error) {
        console.error("Erreur création invitation:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not create the invitation"
        }, 500);
      }
    }
    
    // Générer un jeton personnel pour l'overlay Torn
    if (request.method === "POST" && path === "/overlay/token") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const appUser = await ensureAppUser(
          env,
          account.torn_user_id,
          account.username
        );

        if (!appUser) {
          return json({
            ok: false,
            message: "User not found"
          }, 500);
        }

        const token = await createOverlayToken();
        const tokenHash = await hashOverlayToken(token);

        await env.DB.prepare(`
          INSERT INTO overlay_tokens (user_id, token_hash)
          VALUES (?, ?)
        `).bind(appUser.id, tokenHash).run();

        return json({
          ok: true,
          token,
          message: "Copy this token now: it will not be shown again."
        }, 201);
      } catch (error) {
        console.error(
          "Erreur création jeton overlay:",
          error?.stack || String(error)
        );

        return json({
          ok: false,
          message: "Could not create the token"
        }, 500);
      }
    }

    // Révoquer tous les jetons de l'overlay du compte connecté
    if (
      request.method === "POST" &&
      path === "/overlay/token/revoke"
    ) {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const appUser = await ensureAppUser(
          env,
          account.torn_user_id,
          account.username
        );

        if (!appUser) {
          return json({
            ok: false,
            message: "User not found"
          }, 500);
        }

        await env.DB.prepare(`
          UPDATE overlay_tokens
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
            AND revoked_at IS NULL
        `).bind(appUser.id).run();

        return json({
          ok: true,
          message: "Overlay tokens were revoked"
        });
      } catch (error) {
        console.error(
          "Erreur révocation jeton overlay:",
          error?.stack || String(error)
        );

        return json({
          ok: false,
          message: "Could not revoke the tokens"
        }, 500);
      }
    }

    
    // API de synchronisation pour l'overlay Torn
    if (path === "/overlay/war" || path === "/overlay/war/detect") {
      const overlayAccount = await getOverlayAccount(request, env);
      if (!overlayAccount) return json({ ok: false, message: "Overlay token invalid or revoked" }, 401);
      const acc = await env.DB.prepare(`
        SELECT id, role, torn_user_id FROM accounts WHERE torn_user_id = ? AND active = 1 LIMIT 1
      `).bind(String(overlayAccount.torn_user_id)).first();
      if (!acc) return json({ ok: false, message: "No TornScope account is linked to this token." }, 403);
      try { return await warApi(request, env, acc, path); }
      catch (error) { console.error("War API error:", error?.stack || String(error)); return json({ ok: false, message: "War mode failed" }, 500); }
    }

    if (path === "/api/war" || path === "/api/war/detect") {
      const account = await getAccount(request, env);
      if (!account) return json({ ok: false, message: "Login required" }, 401);
      try { return await warApi(request, env, account, path); }
      catch (error) { console.error("War API error:", error?.stack || String(error)); return json({ ok: false, message: "War mode failed" }, 500); }
    }

    if (path === "/overlay/targets" || path === "/overlay/targets/remove") {
      const overlayAccount = await getOverlayAccount(request, env);

      if (!overlayAccount) {
        return json({
          ok: false,
          message: "Overlay token invalid or revoked"
        }, 401);
      }

      try {
        // Lire la liste du compte authentifié par le jeton
        if (request.method === "GET" && path === "/overlay/targets") {
          const result = await env.DB.prepare(`
            SELECT
              target_torn_id AS tornId,
              target_name AS name,
              last_state AS state,
              last_description AS description,
              last_seen_at AS lastSeenAt
            FROM targets
            WHERE user_id = ?
            ORDER BY target_name COLLATE NOCASE
          `).bind(overlayAccount.user_id).all();

          let premium = { active: false, admin: false, until: null };
          try {
            const acc = await env.DB.prepare(`
              SELECT id, role FROM accounts WHERE torn_user_id = ? AND active = 1 LIMIT 1
            `).bind(String(overlayAccount.torn_user_id)).first();
            if (acc) {
              const info = await premiumInfo(env, acc);
              premium = { active: info.active, admin: Boolean(info.admin), until: info.until || null };
            }
          } catch (error) {
            console.error("Overlay premium status error:", error?.stack || String(error));
          }

          return json({
            ok: true,
            user: {
              tornUserId: String(overlayAccount.torn_user_id),
              username: overlayAccount.username
            },
            premium,
            siteUrl: env.SITE_URL || SITE_URL,
            targets: result.results || []
          });
        }

        // Ajouter un joueur depuis l'overlay
        if (request.method === "POST" && path === "/overlay/targets") {
          const body = await request.json();

          const targetTornId =
            typeof body.targetTornId === "string" ||
            typeof body.targetTornId === "number"
              ? String(body.targetTornId).trim()
              : "";

          if (!/^\d{1,12}$/.test(targetTornId)) {
            return json({
              ok: false,
              message: "Invalid Torn ID"
            }, 400);
          }

          if (
            targetTornId === String(overlayAccount.torn_user_id)
          ) {
            return json({
              ok: false,
              message: "You cannot add your own account"
            }, 400);
          }

          const identity = await verifyTornIdentity(
            env,
            targetTornId
          );

          if (!identity) {
            return json({
              ok: false,
              message: "Player not found or the Torn API is unavailable"
            }, 400);
          }

          const existing = await env.DB.prepare(`
            SELECT id
            FROM targets
            WHERE user_id = ?
              AND target_torn_id = ?
          `).bind(
            overlayAccount.user_id,
            targetTornId
          ).first();

          if (existing) {
            return json({
              ok: true,
              message: "This player is already being watched",
              target: {
                tornId: targetTornId,
                name: identity.name
              }
            });
          }

          await env.DB.prepare(`
            INSERT INTO targets
              (user_id, target_torn_id, target_name)
            VALUES (?, ?, ?)
          `).bind(
            overlayAccount.user_id,
            targetTornId,
            identity.name
          ).run();

          return json({
            ok: true,
            message: "Player added to your watch list",
            target: {
              tornId: targetTornId,
              name: identity.name
            }
          }, 201);
        }

        // Supprimer un joueur depuis l'overlay
        // (POST /overlay/targets/remove sert d'alias pour les clients qui ne savent pas envoyer DELETE, ex. Torn PDA)
        if (
          request.method === "DELETE" ||
          (request.method === "POST" && path === "/overlay/targets/remove")
        ) {
          const body = await request.json();

          const targetTornId =
            typeof body.targetTornId === "string" ||
            typeof body.targetTornId === "number"
              ? String(body.targetTornId).trim()
              : "";

          if (!/^\d{1,12}$/.test(targetTornId)) {
            return json({
              ok: false,
              message: "Invalid Torn ID"
            }, 400);
          }

          const result = await env.DB.prepare(`
            DELETE FROM targets
            WHERE user_id = ?
              AND target_torn_id = ?
          `).bind(
            overlayAccount.user_id,
            targetTornId
          ).run();

          return json({
            ok: true,
            deleted: result.meta.changes > 0,
            message: result.meta.changes > 0
              ? "Player removed from your watch list"
              : "This player was not in the list"
          });
        }

        return json({
          ok: false,
          message: "Method not allowed"
        }, 405, {
          "Allow": "GET, POST, DELETE"
        });
      } catch (error) {
        console.error(
          "Erreur API overlay targets:",
          error?.stack || String(error)
        );

        return json({
          ok: false,
          message: "Error during synchronisation"
        }, 500);
      }
    }

    // Lister les joueurs surveillés par le compte connecté
    if (request.method === "GET" && path === "/targets") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const appUser = await ensureAppUser(
          env,
          account.torn_user_id,
          account.username
        );

        if (!appUser) {
          return json({
            ok: false,
            message: "User not found"
          }, 500);
        }

        const result = await env.DB.prepare(`
          SELECT
            t.target_torn_id AS tornId,
            COALESCE(NULLIF(t.target_name, ''), w.name) AS name,
            COALESCE(w.state, t.last_state) AS state,
            COALESCE(w.description, t.last_description) AS description,
            COALESCE(w.last_polled_at, t.last_seen_at) AS lastSeenAt,
            w.until AS until,
            w.next_poll_at AS nextPollAt,
            w.last_error AS lastError
          FROM targets t
          LEFT JOIN watch_targets w ON w.target_torn_id = t.target_torn_id AND ? = 1
          WHERE t.user_id = ?
          ORDER BY COALESCE(NULLIF(t.target_name, ''), w.name) COLLATE NOCASE
        `).bind((await premiumInfo(env, account)).active ? 1 : 0, appUser.id).all();

        return json({
          ok: true,
          targets: result.results || []
        });
      } catch (error) {
        console.error("Erreur liste cibles:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not load the watched players"
        }, 500);
      }
    }


    // Ajouter un joueur à surveiller
    if (request.method === "POST" && path === "/targets") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const body = await request.json();

        const targetTornId =
          typeof body.targetTornId === "string"
            ? body.targetTornId.trim()
            : typeof body.tornTornId === "string"
              ? body.tornTornId.trim()
              : "";

        if (!/^\d{1,12}$/.test(targetTornId)) {
          return json({
            ok: false,
            message: "Invalid Torn ID"
          }, 400);
        }

        if (targetTornId === String(account.torn_user_id)) {
          return json({
            ok: false,
            message: "You cannot add your own account"
          }, 400);
        }

        const identity = await verifyTornIdentity(env, targetTornId);

        if (!identity) {
          return json({
            ok: false,
            message: "Player not found or the Torn API is unavailable"
          }, 400);
        }

        // IMPORTANT : targets.user_id référence users.id,
        // pas accounts.id.
        const appUser = await ensureAppUser(
          env,
          account.torn_user_id,
          account.username
        );

        if (!appUser) {
          return json({
            ok: false,
            message: "User not found in the database"
          }, 500);
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM targets
          WHERE user_id = ?
            AND target_torn_id = ?
        `).bind(appUser.id, targetTornId).first();

        if (existing) {
          return json({
            ok: true,
            message: "This player is already being watched",
            target: {
              tornId: targetTornId,
              name: identity.name
            }
          });
        }

        await env.DB.prepare(`
          INSERT INTO targets
            (user_id, target_torn_id, target_name)
          VALUES (?, ?, ?)
        `).bind(
          appUser.id,
          targetTornId,
          identity.name
        ).run();

        return json({
          ok: true,
          message: "Player added to your watch list",
          target: {
            tornId: targetTornId,
            name: identity.name
          }
        }, 201);
      } catch (error) {
        console.error("Erreur ajout cible:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not add this player"
        }, 500);
      }
    }
    
    // Supprimer un joueur surveillé depuis le tableau de bord
    if (request.method === "DELETE" && path === "/targets") {
      const account = await getAccount(request, env);

      if (!account) {
        return json({
          ok: false,
          message: "Login required"
        }, 401);
      }

      try {
        const body = await request.json();

        const targetTornId =
          typeof body.targetTornId === "string" ||
          typeof body.targetTornId === "number"
            ? String(body.targetTornId).trim()
            : "";

        if (!/^\d{1,12}$/.test(targetTornId)) {
          return json({
            ok: false,
            message: "Invalid Torn ID"
          }, 400);
        }

        // IMPORTANT : targets.user_id référence users.id,
        // pas accounts.id.
        const appUser = await ensureAppUser(
          env,
          account.torn_user_id,
          account.username
        );

        if (!appUser) {
          return json({
            ok: false,
            message: "User not found in the database"
          }, 500);
        }

        const result = await env.DB.prepare(`
          DELETE FROM targets
          WHERE user_id = ?
            AND target_torn_id = ?
        `).bind(appUser.id, targetTornId).run();

        return json({
          ok: true,
          deleted: result.meta.changes > 0,
          message: result.meta.changes > 0
            ? "Player removed from your watch list"
            : "This player was not in the list"
        });
      } catch (error) {
        console.error("Erreur suppression cible:", error?.stack || String(error));

        return json({
          ok: false,
          message: "Could not remove this player"
        }, 500);
      }
    }

    // Interface web : page d'accueil
    if (request.method === "GET" && (path === "/" || path === "/index.html")) {
      return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b1020">
  <link rel="icon" type="image/svg+xml" href="${FAVICON}">
  <title>TornScope</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: #0b1020;
      color: #f1f5f9;
      font-family: Inter, system-ui, Arial, sans-serif;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .container { width: 100%; max-width: 760px; }
    .brand {
      display: flex; align-items: center; gap: 14px;
      margin-bottom: 38px;
    }
    .logo {
      width: 52px; height: 52px; border-radius: 15px;
      background: none; color: #16d9f2;
      display: grid; place-items: center;
    }
    h1 { margin: 0; font-size: clamp(23px, 5vw, 34px); }
    .subtitle { color: #94a3b8; margin-top: 6px; font-size: 13px; }
    .panel {
      background: #111a2e; border: 1px solid #26334d;
      border-radius: 20px; padding: clamp(22px, 5vw, 36px);
    }
    .status {
      display: inline-flex; align-items: center; gap: 8px;
      color: #6ee7b7; background: #12332f;
      border-radius: 30px; padding: 7px 11px; font-size: 12px;
    }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: #34d399; }
    h2 { font-size: 23px; margin: 24px 0 10px; }
    p { color: #aab7ce; line-height: 1.7; }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 25px; }
    a {
      display: inline-block; text-decoration: none; border-radius: 10px;
      padding: 12px 18px; font-weight: 650; font-size: 14px;
    }
    .primary { background: #0e7490; color: white; }
    .secondary { border: 1px solid #394663; color: #e2e8f0; }
    footer { color: #64748b; font-size: 12px; text-align: center; margin-top: 24px; }
  </style>
</head>
<body>
  <main class="container">
    <header class="brand">
      <div class="logo">${LOGO_SVG}</div>
      <div>
        <h1>TornScope</h1>
        <div class="subtitle">PLAYER TRACKING · TORN CITY</div>
      </div>
    </header>
    <section class="panel">
      <span class="status"><span class="dot"></span> SERVICE ONLINE</span>
      <h2>Keep every target in your scope.</h2>
      <p>
        Follow the players you watch and review their activity (travel today,
        more tools to come) from a dashboard built for Torn.
      </p>
      <div class="actions">
        <a class="primary" href="/app">Log in with your API key</a>
        <a class="secondary" href="${SCRIPT_URL}" target="_blank" rel="noopener noreferrer">Install the script</a>
        <a class="secondary" href="/health">Server status</a>
      </div>
    </section>
    <footer>TornScope · Secure account access · <a href="/terms">API key and data use</a></footer>
  </main>
</body>
</html>`, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }


    // Page de connexion
    if (request.method === "GET" && path === "/app") {
      return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0b1020">
  <link rel="icon" type="image/svg+xml" href="${FAVICON}">
  <title>Login — TornScope</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; padding: 24px;
      display: grid; place-items: center;
      background: #0b1020; color: #f1f5f9;
      font-family: Inter, system-ui, Arial, sans-serif;
    }
    .card {
      width: 100%; max-width: 420px; padding: 30px;
      background: #111a2e; border: 1px solid #26334d;
      border-radius: 20px;
    }
    .logo { width: 52px; height: 52px; }
    h1 { font-size: 25px; margin: 12px 0 8px; }
    p { color: #94a3b8; line-height: 1.6; }
    label { display: block; margin: 18px 0 7px; font-size: 14px; }
    input {
      width: 100%; padding: 12px; border-radius: 9px;
      border: 1px solid #394663; background: #0b1020;
      color: white; font-size: 16px;
    }
    button {
      width: 100%; margin-top: 24px; padding: 13px;
      border: 0; border-radius: 10px; cursor: pointer;
      background: #0e7490; color: white;
      font-weight: 700; font-size: 15px;
    }
    #message { margin-top: 16px; font-size: 14px; overflow-wrap: anywhere; }
    a { color: #67e8f9; }
    .signup { margin-top: 22px; padding: 14px; border: 1px solid #26334d; border-radius: 12px; text-align: center; font-size: 14px; color: #94a3b8; }
    .signup-btn { display: block; margin-top: 10px; padding: 11px; border-radius: 10px; border: 1px solid #0e7490; color: #67e8f9; font-weight: 700; text-decoration: none; }
    .signup-btn:hover { background: rgba(14, 116, 144, .18); }
    .ck { display: flex; align-items: center; gap: 10px; margin: 14px 0 0; font-size: 14px; color: #cbd5e1; }
    .ck input { width: auto; margin: 0; }
  </style>
</head>
<body>
  <main class="card">
    <div class="logo">${LOGO_SVG}</div>
    <h1>Log in with your Torn API key</h1>
    <p>No password and no sign-up form: paste a <b>Public</b> Torn API key. Your account is created automatically the first time.</p>
    <form id="keyForm">
      <label for="apikey">Torn API key (Public access)</label>
      <input id="apikey" name="apikey" type="password" autocomplete="off" spellcheck="false" required minlength="16" maxlength="16" placeholder="16 characters">
      <label class="ck"><input type="checkbox" id="remember" checked> Keep me logged in</label>
      <label class="ck"><input type="checkbox" id="agree" required> <span>I agree to the <a href="/terms" target="_blank" rel="noopener noreferrer">data and API key use</a></span></label>
      <button type="submit">Log in</button>
      <div id="keyMessage" role="status" aria-live="polite"></div>
    </form>
    <div class="signup" style="text-align:left">
      Don't have a key? <a href="https://www.torn.com/preferences.php#tab=api?step=addNewKey&amp;title=TornScope&amp;user=basic" target="_blank" rel="noopener noreferrer">Create one</a> (Public access is enough; keys with more access are refused).<br><br>
      <b>What happens to your key</b><br>
      It is sent once to Torn to check who you are, then discarded: it is not stored. Nothing is sold or shared.
      <a href="/terms">Full details</a>
    </div>
    <details style="margin-top:18px">
      <summary style="cursor:pointer;color:#94a3b8;font-size:14px">I have a username and password</summary>
      <form id="loginForm">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required maxlength="64">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="128">
        <button type="submit">Log in with password</button>
        <div id="message" role="status" aria-live="polite"></div>
      </form>
      <p><a href="/reset">Forgot your password? I have a reset code</a></p>
    </details>
    <div class="signup">
      <a class="signup-btn" href="${SCRIPT_URL}" target="_blank" rel="noopener noreferrer">Install the script</a>
    </div>
    <p><a href="/terms">How your data and API key are used</a></p>
    <p><a href="/">← Back to home</a></p>
  </main>
  <script>
    const form = document.getElementById("loginForm");
    const message = document.getElementById("message");
    const keyForm = document.getElementById("keyForm");
    const keyMessage = document.getElementById("keyMessage");

    keyForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      keyMessage.textContent = "Checking with Torn…";
      const value = keyForm.apikey.value.trim();
      keyForm.apikey.value = "";
      try {
        const response = await fetch("/login-key", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ key: value, remember: keyForm.remember.checked, agree: keyForm.agree.checked })
        });
        const result = await response.json();
        if (!response.ok || !result.ok) {
          keyMessage.textContent = result.message || "Could not log in.";
          return;
        }
        window.location.href = "/dashboard";
      } catch {
        keyMessage.textContent = "Could not reach the server. Try again.";
      }
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      message.textContent = "Logging in…";

      try {
        const response = await fetch("/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            username: form.username.value.trim(),
            password: form.password.value
          })
        });

        const result = await response.json();

        if (!response.ok || !result.ok) {
          message.textContent = result.message || "Could not log in.";
          return;
        }

        window.location.href = "/dashboard";
      } catch {
        message.textContent = "Could not reach the server. Try again.";
      }
    });
  </script>
</body>
</html>`, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      });
    }
    
    // Tableau de bord protégé
    if (request.method === "GET" && path === "/dashboard") {
      const account = await getAccount(request, env);

      if (!account) {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/app",
            "Cache-Control": "no-store"
          }
        });
      }

      return new Response(DASHBOARD_HTML, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY"
        }
      });
    }


    return json({
      ok: false,
      message: "Unknown route"
    }, 404);
  },

  // Cron Trigger: runs every minute with no user, browser or userscript involved.
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      const startedMs = Date.now();
      try {
        rememberOwnerKeys(env);
        if (!env.DB) {
          console.error("Collector: DB binding missing");
          return;
        }

        let reserve = 0;
        try {
          const xan = await ownerXanaxCheck(env);
          if (xan.ran) reserve = XANAX_RESERVE;
          if (xan.credited || xan.pending) console.log("Xanax check", JSON.stringify(xan));
        } catch (error) {
          console.error("Xanax check failed:", error?.name || "error");
          reserve = XANAX_RESERVE;
        }

        try {
          const war = await warCollect(env);
          if (war.ran) { reserve += war.reserve; if (war.changed) console.log("War check", JSON.stringify(war)); }
        } catch (error) {
          console.error("War check failed:", error?.name || "error");
          reserve += 11;
        }

        try {
          const radar = await radarCollect(env, reserve);
          if (radar.ran) { reserve += radar.reserve; if (radar.flights || radar.landings || radar.errors) console.log("Radar check", JSON.stringify(radar)); }
        } catch (error) {
          console.error("Radar check failed:", error?.name || "error");
          reserve += 8;
        }

        try {
          const stock = await stockCollect(env);
          if (stock.ran) { reserve += stock.reserve; if (stock.events || stock.error) console.log("Stock check", JSON.stringify(stock)); }
        } catch (error) {
          console.error("Stock check failed:", error?.name || "error");
          reserve += 3;
        }

        const summary = await collect(env, "cron", reserve);
        console.log("Collector run", JSON.stringify({
          due: summary.due, polled: summary.polled, ok: summary.ok,
          errors: summary.errors, events: summary.events, deferred: summary.deferred,
          ms: summary.durationMs, note: summary.note
        }));
        // Extra passes inside the minute (paid plan only): the radar's second pass at ~30 s, and more stock reads if STOCK_POLLS_PER_MIN > 1.
        try {
          if (Number(env.RADAR_MAX) > RADAR_MAX_PER_RUN) {
            const cfgDelay = env.RADAR_PASS2_DELAY_S === undefined ? 30 : Number(env.RADAR_PASS2_DELAY_S);
            const radarAt = Number.isFinite(cfgDelay) ? cfgDelay : 30;
            const perMin = Math.max(1, Math.min(12, Math.floor(Number(env.STOCK_POLLS_PER_MIN) || 1)));
            const spacing = env.STOCK_PASS_SPACING_S !== undefined && Number.isFinite(Number(env.STOCK_PASS_SPACING_S)) ? Number(env.STOCK_PASS_SPACING_S) : 60 / perMin;
            const tasks = [{ at: radarAt, kind: "radar" }];
            if (/^https:\/\//.test(String(env.STOCK_FEED_URL || ""))) for (let i = 1; i < perMin; i++) tasks.push({ at: spacing * i, kind: "stock" });
            tasks.sort((a, b) => a.at - b.at);
            for (const t of tasks) {
              const wait = Math.max(0, t.at * 1000 - (Date.now() - startedMs));
              if (wait > 0) await new Promise(r => setTimeout(r, wait));
              try {
                if (t.kind === "radar") {
                  const r2 = await radarCollect(env, 0);
                  if (r2.flights || r2.landings || r2.errors) console.log("Radar pass 2", JSON.stringify(r2));
                } else {
                  const st = await stockCollect(env);
                  if (st.events || st.error) console.log("Stock check", JSON.stringify(st));
                }
              } catch (error) {
                console.error(t.kind + " extra pass failed:", error?.name || "error");
              }
            }
          }
        } catch (error) {
          console.error("Extra passes failed:", error?.name || "error");
        }
        await flushUsage(env);
      } catch (error) {
        console.error("Collector crashed:", error?.stack || String(error));
      }
    })());
  }
};

export default TS_WORKER;
