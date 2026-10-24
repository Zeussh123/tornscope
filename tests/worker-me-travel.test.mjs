// End-to-end test of GET /api/me/travel on a Worker file with a mocked D1 and a mocked Torn API.
import assert from 'assert';
const file = process.argv[2];
const mod = await import(new URL('file://' + process.cwd() + '/' + file));
const W = mod.default, enc = new TextEncoder();
const SECRET = 'x'.repeat(40), ACCOUNT_ID = 7, KEY = 'AbCdEfGhIjKlMnOp';
async function vaultEnc(plain) {
  const base = await crypto.subtle.importKey('raw', enc.encode(SECRET), 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode('ttw-key-vault'), info: enc.encode('user-api-key-v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode('ttw-user-key:' + ACCOUNT_ID) }, key, enc.encode(plain)));
  const b64 = (u) => btoa(String.fromCharCode(...u));
  return 'v1.' + b64(iv) + '.' + b64(c);
}
let hasKey = true, locked = false, tornAnswer = null, tornCalls = [];
const stored = await vaultEnc(KEY);
const db = { exec: async () => ({}), prepare(sql) { let binds = []; const q = { bind(...b) { binds = b; return q; },
  async first() {
    if (/FROM sessions/.test(sql)) return { id: ACCOUNT_ID, username: 'tester', torn_user_id: '1', role: 'user' };
    if (/FROM user_keys/.test(sql)) return hasKey ? { enc: stored, status: 'valid' } : null;
    if (/FROM auth_attempts/.test(sql)) return locked ? { locked_until: Math.floor(Date.now() / 1000) + 60 } : null;
    return null; },
  async all() { return { results: [] }; }, async run() { return { meta: { changes: 1 } }; } }; return q; }, async batch() { return []; } };
const env = { DB: db, TORN_API_KEY: 'OWNERKEY00000000', APP_SECRET: 's', KEY_ENCRYPTION_SECRET: SECRET };
globalThis.fetch = async (url) => { tornCalls.push(String(url)); return new Response(JSON.stringify(tornAnswer), { status: 200 }); };
const call = async () => { const r = await W.fetch(new Request('https://app.test/api/me/travel', { headers: { Cookie: 'ttw_session=' + 'a'.repeat(64) } }), env, { waitUntil() {} }); return { status: r.status, body: await r.json() }; };
const nowS = () => Math.floor(Date.now() / 1000);

tornAnswer = { travel: { destination: 'Torn', time_left: 600, method: 'Airstrip' } };
let r = await call(); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.pos.state, 'flying'); assert.strictEqual(r.body.pos.direction, 'return');
assert(Math.abs(r.body.pos.landAt - (nowS() + 600)) <= 2);
assert(tornCalls.some(u => u.includes('selections=travel') && u.includes('key=' + KEY)), 'uses the member key with selections=travel');

tornAnswer = { travel: { destination: 'Cayman Islands', time_left: 1200 } };
r = await call(); assert.deepStrictEqual([r.body.pos.state, r.body.pos.direction, r.body.pos.country], ['flying', 'out', 'Cayman Islands']);
tornAnswer = { travel: { destination: 'Japan', time_left: 0 } };
r = await call(); assert.deepStrictEqual([r.body.pos.state, r.body.pos.country], ['abroad', 'Japan']);
tornAnswer = { travel: { destination: 'Torn', time_left: 0 } };
r = await call(); assert.strictEqual(r.body.pos.state, 'torn');
tornAnswer = { error: { code: 2, error: 'Incorrect key' } };
r = await call(); assert.strictEqual(r.status, 400);
assert(!JSON.stringify(r.body).includes(KEY), 'key never in the answer');
hasKey = false; r = await call(); assert.strictEqual(r.status, 404); assert.strictEqual(r.body.needKey, true);
hasKey = true; locked = true; r = await call(); assert.strictEqual(r.status, 429);
console.log('worker /api/me/travel: all checks passed');
