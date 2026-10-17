/* Coach instance configuration on the Worker — the port of api/coach/config.js.
 *
 * Same design, different bytes: the Node server keeps its settings in ./data/coach.json
 * because the admin-dashboard flow is the whole point (enabling the Coach never requires
 * editing a file or restarting the stack); here they are one row of the Durable Object's
 * docs table ('coach:config'), which is transactional and never torn. The one env knob is
 * COACH_DISABLED, the fleet operator's kill switch, exactly as on the Node server.
 *
 * Credentials are encrypted at rest exactly as there (AES-256-GCM), but with WebCrypto
 * instead of node:crypto — workerd's HKDF/cipher surface is thinner, and subtle is native.
 * The key is HKDF-SHA256 of the instance secret (the same kv 'secret' the session HMAC
 * uses) with its own info string, so the two never share a key.
 *
 * Only the plain-HTTPS providers exist on this deployment (see adapters.js): no CLI
 * runtime can be spawned inside a Worker, so claude/codex/fixture are not offered and
 * the default provider is 'compatible' — an OpenAI-compatible endpoint, which is what
 * this instance is meant to run on.
 */
import { HTTP_PROVIDERS, baseUrlFor } from './core/providers.js';
import { MAX_OUTPUT_TOKENS } from './core/adapters/http.js';

export const PROVIDERS = { ...HTTP_PROVIDERS };

export const MAX_MESSAGE_LEN_FLOOR = 200;
export const MAX_MESSAGE_LEN_CEILING = 4000;
export const MAX_OUTPUT_TOKENS_FLOOR = 1024;
export const MAX_OUTPUT_TOKENS_CEILING = 65536;

const DEFAULTS = {
  enabled: false,
  provider: 'compatible',
  authMode: 'instance',                              // 'instance' | 'profile'
  // Everything a provider owns is keyed by provider, so switching never throws a key away.
  auth: {},                                          // instance mode: { [provider]: { type, account, data:<encrypted>, connectedAt } }
  models: {},                                        // { [provider]: model id }
  providerOptions: {},                               // { [provider]: { baseUrl, headers } }
  boundUid: {},                                      // instance mode: { [provider]: the profile its credential bound to }
  caps: { perProfileDaily: 10, instanceDaily: 0 },   // 0 = unlimited
  daily: null,                                       // { date, count }: jobs enqueued today across every profile
  community: false,
  maxMessageLen: 1000,
  maxOutputTokens: MAX_OUTPUT_TOKENS,
  log: []
};
const PER_PROVIDER = ['auth', 'models', 'providerOptions', 'boundUid'];
const isPlainObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
const LOG_MAX = 100;
const CONFIG_KEY = 'coach:config';
const userKey = uid => 'coach:user:' + String(uid).replace(/[^a-zA-Z0-9_-]/g, '');
const profileAuthKey = uid => 'coach:auth:' + String(uid).replace(/[^a-zA-Z0-9_-]/g, '');

export const SHARED_ACCOUNT_REFUSAL =
  'This instance is configured with a single shared account. Ask your admin to enable per-profile sign-in.';

/* The per-user record shape (api/coach/jobs.js EMPTY): the proposal the server owns,
   the job in flight, today's spend and the recent outcome history. */
const EMPTY_USER = { daily: null, current: null, pending: null, history: [] };

export class Coach {
  constructor({ sql, env, secret, readState, listUserIds, waitUntil }) {
    this.sql = sql;
    this.env = env || {};
    this.secret = String(secret || '');
    this._readState = readState;
    this._listUserIds = listUserIds;
    this._waitUntil = waitUntil;
    this.cache = null;
    this._ckey = null;
    // The job queue (see jobs.js) lives here because the DO is the single thread this
    // instance has, the same in-process shape the Node server keeps.
    this.queue = [];
    this.running = 0;
    this.inflight = new Set();      // uids with a job queued or running (single-flight)
    this.forgetSeq = new Map();     // uid → bumped by every clearUser
    this.aborts = new Map();        // uid → AbortController of the provider call in flight
    this.cohortCache = null;
  }

  get COACH_DISABLED() { return /^(1|true|yes|on)$/i.test(this.env.COACH_DISABLED || ''); }

  /* ---------- config load / save ---------- */

  load() {
    if (this.cache) return this.cache;
    let stored = {};
    try {
      const row = this.sql.exec(`SELECT value FROM docs WHERE key = ?`, CONFIG_KEY).toArray()[0];
      if (row) stored = JSON.parse(row.value);
    } catch { /* absent = feature off */ }
    const cache = { ...DEFAULTS, ...stored, caps: { ...DEFAULTS.caps, ...(stored.caps || {}) } };
    // Every per-provider map holds only providers this build knows (see config.js).
    for (const k of PER_PROVIDER) {
      const src = isPlainObj(cache[k]) ? cache[k] : {};
      const clean = {};
      for (const p of Object.keys(src)) if (Object.prototype.hasOwnProperty.call(PROVIDERS, p)) clean[p] = src[p];
      cache[k] = clean;
    }
    if (!PROVIDERS[cache.provider]) cache.provider = DEFAULTS.provider;
    if (cache.authMode !== 'profile') cache.authMode = 'instance';
    this.cache = cache;
    return cache;
  }
  save(patch) {
    const next = { ...this.load(), ...patch };
    this.cache = next;
    this.sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES (?, ?)`, CONFIG_KEY, JSON.stringify(next));
    return next;
  }
  // Test seam: forget the in-memory copy so the next load() re-reads from storage.
  reset() { this.cache = null; this._ckey = null; }

  /* ---------- at-rest encryption (WebCrypto AES-256-GCM, HKDF off the instance secret) ---------- */

  async ckey() {
    if (this._ckey) return this._ckey;
    const enc = new TextEncoder();
    const ikm = await crypto.subtle.importKey('raw', enc.encode(this.secret), 'HKDF', false, ['deriveKey']);
    this._ckey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('opengym-coach-worker-v1') },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return this._ckey;
  }
  async encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await this.ckey(), new TextEncoder().encode(JSON.stringify(obj)));
    return Buffer.from(iv).toString('base64') + '.' + Buffer.from(ct).toString('base64');
  }
  async decrypt(blob) {
    try {
      const [ivB64, ctB64] = String(blob || '').split('.');
      if (!ivB64 || !ctB64) return null;
      const iv = new Uint8Array(Buffer.from(ivB64, 'base64'));
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await this.ckey(), Buffer.from(ctB64, 'base64'));
      return JSON.parse(new TextDecoder().decode(pt));
    } catch { return null; }   // wrong key, or tampered row
  }

  /* ---------- what one provider owns ---------- */

  authFor(cfg = this.load(), p = cfg.provider) { return (cfg.auth && cfg.auth[p]) || null; }
  modelFor(cfg = this.load(), p = cfg.provider) { return (cfg.models && cfg.models[p]) || (PROVIDERS[p] && PROVIDERS[p].defaultModel) || null; }
  optionsFor(cfg = this.load(), p = cfg.provider) { return (cfg.providerOptions && cfg.providerOptions[p]) || {}; }
  boundUidFor(cfg = this.load(), p = cfg.provider) { return (cfg.boundUid && cfg.boundUid[p]) || null; }
  providerMeta(cfg = this.load()) { return PROVIDERS[(cfg || this.load()).provider] || PROVIDERS.compatible; }
  async saveAuth(provider, auth) {
    const cfg = this.load();
    const next = { ...cfg.auth };
    if (auth) next[provider] = auth; else delete next[provider];
    // boundUid resets with the credential: a new account has not been spent by anyone yet.
    const bound = { ...cfg.boundUid }; delete bound[provider];
    return this.save({ auth: next, boundUid: bound });
  }
  saveModel(provider, model) {
    const next = { ...this.load().models };
    if (model) next[provider] = model; else delete next[provider];
    return this.save({ models: next });
  }
  saveOptions(provider, patch) {
    const all = { ...this.load().providerOptions };
    all[provider] = { ...(all[provider] || {}), ...patch };
    return this.save({ providerOptions: all });
  }

  /* ---------- per-profile credentials ---------- */

  async loadProfileAuth(uid) {
    try {
      const row = this.sql.exec(`SELECT value FROM docs WHERE key = ?`, profileAuthKey(uid)).toArray()[0];
      return row ? JSON.parse(row.value) : null;
    } catch { return null; }
  }
  async saveProfileAuth(uid, auth) {
    this.sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES (?, ?)`, profileAuthKey(uid), JSON.stringify(auth));
    return auth;
  }
  async clearProfileAuth(uid) {
    this.sql.exec(`DELETE FROM docs WHERE key = ?`, profileAuthKey(uid));
  }

  /* ---------- which credential pays for this job ---------- */

  /**
   * Resolve the credential for one profile, or say why there isn't one. Never throws and
   * never returns a token to a caller that only asked whether a job may run. The port of
   * config.js credentialFor — async because decrypt is WebCrypto here.
   */
  async credentialFor(uid) {
    const cfg = this.load();
    if (cfg.authMode === 'profile') {
      const rec = await this.loadProfileAuth(uid);
      const auth = rec && rec.data ? await this.decrypt(rec.data) : null;
      if (!auth || !auth.token) return { ok: false, reason: 'no-credential', mode: 'profile' };
      return { ok: true, auth, type: rec.type, account: rec.account || null, mode: 'profile' };
    }
    // instance mode
    const bound = this.boundUidFor(cfg);
    if (bound && bound !== uid) {
      return { ok: false, reason: 'shared-account', message: SHARED_ACCOUNT_REFUSAL, mode: 'instance' };
    }
    const rec = this.authFor(cfg);
    const auth = rec && rec.data ? await this.decrypt(rec.data) : null;
    if (!auth || !auth.token) {
      // An endpoint that takes no key (a model on the LAN) is connected without one. Only when
      // nothing was ever filed — a filed key that fails to decrypt is still a failure.
      if (this.providerMeta(cfg).keyOptional && !rec) return { ok: true, auth: null, type: null, account: null, mode: 'instance' };
      return { ok: false, reason: 'no-credential', mode: 'instance' };
    }
    return { ok: true, auth, type: rec.type, account: rec.account || null, mode: 'instance' };
  }

  // A personal credential (setup token, OAuth) is one person's subscription; an API key is
  // metered and shared by every profile under the daily caps. See config.js for the posture.
  isPersonalCredential(type) { return type === 'cli-token' || type === 'oauth'; }
  async bindInstanceCredential(uid) {
    const cfg = this.load();
    const rec = this.authFor(cfg);
    if (cfg.authMode === 'instance' && !this.boundUidFor(cfg) && rec && this.isPersonalCredential(rec.type)) {
      await this.save({ boundUid: { ...cfg.boundUid, [cfg.provider]: uid } });
    }
  }

  /** Whose account a profile is about to spend — rendered in the UI, never a secret. */
  async accountFor(uid) {
    const cfg = this.load();
    const c = await this.credentialFor(uid);
    return {
      mode: cfg.authMode,
      provider: cfg.provider,
      providerLabel: this.providerMeta(cfg).label,
      account: c.ok ? (c.account || null) : null,
      connected: !!c.ok,
      reason: c.ok ? null : c.reason,
      message: c.ok ? null : (c.message || null)
    };
  }

  /* ---------- derived state ---------- */

  /** Is the feature switched on at all (before asking whether it can reach a model)? */
  isEnabled() {
    if (this.COACH_DISABLED) return false;
    const cfg = this.load();
    return !!cfg.enabled && !!PROVIDERS[cfg.provider];
  }
  /** Can this instance reach a model for anybody? (config.js isConnected, async for decrypt.) */
  async isConnected() {
    const cfg = this.load();
    if (!this.isEnabled()) return false;
    if (cfg.authMode === 'profile') return true;
    const rec = this.authFor(cfg);
    if (!rec) return !!this.providerMeta(cfg).keyOptional && !!baseUrlFor(cfg.provider, cfg);
    return !!(await this.decrypt(rec.data));
  }
  /** What /api/config tells every client. Absent ⇒ no Coach UI exists anywhere. */
  async publicConfig() {
    if (!this.isEnabled() || !(await this.isConnected())) return null;
    const cfg = this.load();
    return { enabled: true, provider: cfg.provider, providerLabel: this.providerMeta(cfg).label, authMode: cfg.authMode, community: !!cfg.community };
  }

  /**
   * The "environment" a job's provider call gets. On the Node server this is a sanitised
   * env for a child process; here there is no child — the HTTP adapters read the key out of
   * this plain object and nothing else, which keeps the same single channel the credential
   * can travel down (the adapter never sees the store).
   */
  jobEnv(resolved) {
    const meta = this.providerMeta();
    const env = {};
    const auth = resolved && resolved.auth;
    if (auth && auth.token) {
      const name = this.isPersonalCredential(resolved.type) ? (meta.oauthEnv || meta.apiKeyEnv) : meta.apiKeyEnv;
      if (name) env[name] = auth.token;
    }
    return env;
  }

  /* ---------- per-user records ---------- */

  readUser(uid) {
    try {
      const row = this.sql.exec(`SELECT value FROM docs WHERE key = ?`, userKey(uid)).toArray()[0];
      return row ? { ...EMPTY_USER, ...JSON.parse(row.value) } : { ...EMPTY_USER };
    } catch { return { ...EMPTY_USER }; }
  }
  writeUser(uid, rec) {
    this.sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES (?, ?)`, userKey(uid), JSON.stringify(rec));
  }
  patchUser(uid, patch) {
    const rec = { ...this.readUser(uid), ...patch };
    this.writeUser(uid, rec);
    return rec;
  }
  listCoachUserIds() {
    return this.sql.exec(`SELECT key FROM docs WHERE key LIKE 'coach:user:%'`)
      .toArray().map(r => r.key.slice('coach:user:'.length));
  }

  /* ---------- the synced state document (owned by the DO, read here) ---------- */

  readState(uid) { return this._readState(uid); }
  listUserIds() { return this._listUserIds(); }

  /* ---------- caps ---------- */

  todayISO() { return new Date().toISOString().slice(0, 10); }
  capState(uid) {
    const caps = this.load().caps || {};
    const rec = this.readUser(uid);
    const used = rec.daily?.date === this.todayISO() ? rec.daily.count : 0;
    return { used, limit: caps.perProfileDaily || 0 };
  }
  bumpDaily(uid) {
    const rec = this.readUser(uid);
    const d = this.todayISO();
    const daily = rec.daily?.date === d ? { date: d, count: rec.daily.count + 1 } : { date: d, count: 1 };
    this.patchUser(uid, { daily });
    return daily.count;
  }
  bumpInstanceDaily() {
    const cur = this.load().daily;
    const d = this.todayISO();
    this.save({ daily: cur?.date === d ? { date: d, count: cur.count + 1 } : { date: d, count: 1 } });
  }
  instanceUsedToday() {
    const daily = this.load().daily;
    return daily?.date === this.todayISO() ? daily.count : 0;
  }

  /* ---------- instance-level job log (counts and outcomes only, never contents) ---------- */

  logJob(entry) {
    const log = [...(this.load().log || []), entry].slice(-LOG_MAX);
    this.save({ log });
  }
  lastError() { return [...(this.load().log || [])].reverse().find(e => e.outcome === 'failed') || null; }
  lastSuccess() { return [...(this.load().log || [])].reverse().find(e => e.outcome === 'ready' || e.outcome === 'nochange') || null; }
}
