/* opengym-api on Cloudflare Workers — the whole API as one Durable Object.
 *
 * Ported from api/server.js (Node, no framework). That server is single-instance by
 * design — one db.json in memory, one state-<uid>.json per profile, in-memory challenge
 * and pairing stores — and this DO keeps exactly that shape, single-threaded inside one
 * object. What changed is only where the bytes land:
 *
 *   db.json (+ .bak)      docs table, key 'db'          (the fsync/.bak dance is gone:
 *                                                        DO storage is transactional)
 *   state-<uid>.json      docs table, key 'state:<uid>'
 *   secret               kv table, key 'secret'        (session HMAC key, as today)
 *   audit.log            audit table, one row per event
 *   challenges/pairings   kv table with an expiry        (survive DO eviction, unlike the
 *                                                        Node process's in-memory Maps)
 *
 * Not ported (yet): media uploads (R2), the password routes (scrypt needs the paid
 * plan's CPU), push, the rest of the admin dashboard. The Coach IS here (workers/src/coach/):
 * configured through the admin dashboard, jobs on the plain-HTTPS adapters, scheduled
 * reviews on the alarm. Passkey sign-in, pairing, the sync protocol and the Coach — the
 * heart of the app — are here in full.
 */
import crypto from 'node:crypto';
import { DurableObject } from 'cloudflare:workers';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { stampPut } from './sync-stamps.js';
import { verifyError } from './verify-error.js';
import { createDeviceLink, findDeviceLink, burnDeviceLink, dropDeviceLinks } from './device-link.js';
import { createWindow, createBackoff } from './rate-limit.js';
import {
  listPasskeys, addPasskeyRecord, renamePasskeyRecord, removePasskeyRecord,
  passkeyRemovalRefused, MAX_PASSKEYS
} from './passkeys-store.js';
import { Coach } from './coach/store.js';
import * as coachJobs from './coach/jobs.js';
import { coachRoutes } from './coach/routes.js';
import { tick as coachTick } from './coach/cadence.js';

const MINUTE = 60000;
const MAX_BODY = 5 * 1024 * 1024;
// How many earlier write ids a state document keeps (see PUT /api/data).
const WID_KEEP = 50;
// When a profile last fetched its document; written at most every ten minutes per profile.
const PULL_NOTE_MS = 10 * MINUTE;

const ON = /^(1|true|yes|on)$/i;
const OFF = /^(0|false|no|off)$/i;

export class Db extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
    this.sql = ctx.storage.sql;
    // Ephemeral, never persisted — the same contract the Node process has.
    this.presence = new Map();
    // A flood of failed ceremonies must not push real events out of the log (auditFail).
    this.failAudit = createWindow({ max: 10, windowMs: MINUTE });
    this.failAuditAll = createWindow({ max: 120, windowMs: MINUTE });
    // The sign-in throttle the device-link routes are counted against (see api/server.js):
    // a burst budget per address, and a pause after enough wrong codes. Passkey sign-in and
    // registration stay out of it, as they always were — nothing there is worth guessing.
    this.authBurst = createWindow({ max: 60, windowMs: MINUTE });
    this.addrFails = createBackoff({ free: 20, baseMs: 30000, maxMs: 15 * MINUTE, forgetMs: 3600000 });
    this.ready = this.boot();
  }

  /* ---------- environment (the same variables api/server.js reads) ---------- */
  get RP_ID() { return this.env.RP_ID || 'localhost'; }
  get ORIGIN() { return this.env.ORIGIN || 'http://localhost:8080'; }
  get RP_NAME() { return this.env.RP_NAME || 'openGym'; }
  get INVITE_ONLY() { return ON.test(this.env.INVITE_ONLY || ''); }
  get ALLOW_GUEST() { return !OFF.test(this.env.ALLOW_GUEST || ''); }
  get FIRST_USER_ADMIN() { return ON.test(this.env.FIRST_USER_ADMIN || ''); }
  get ADMIN_UIDS() { return (this.env.ADMIN_UIDS || '').split(',').map(s => s.trim()).filter(Boolean); }
  get AUDIT_ON() { return !OFF.test(this.env.AUDIT_LOG || ''); }
  get AUDIT_MAX() { return Math.max(0, +(this.env.AUDIT_MAX || 5000) || 0); }
  get AUDIT_DAYS() { return Math.max(0, +(this.env.AUDIT_DAYS || 90) || 0); }
  get SESSION_DAYS() { return Math.max(1, +(this.env.SESSION_DAYS || 90) || 90); }
  get SECURE() { return /^https:/i.test(this.ORIGIN) ? ' Secure;' : ''; }
  // Google sign-in exists only where both halves of the OAuth client are configured; without
  // them the routes answer 404 and /api/config says nothing, which is how the client knows.
  get GOOGLE() { return !!(this.env.GOOGLE_CLIENT_ID && this.env.GOOGLE_CLIENT_SECRET); }
  googleRedirect() { return this.ORIGIN.replace(/\/+$/, '') + '/api/auth/google/callback'; }

  /* ---------- storage ---------- */
  async boot() {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS docs (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, exp INTEGER)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ev TEXT NOT NULL, ok INTEGER,
      uid TEXT, name TEXT, tgt TEXT, tname TEXT, msg TEXT, ip TEXT)`);
    // The session HMAC key. One per instance, made on first boot, never rotated (rotating it
    // signs out every device — delete the row to do that on purpose).
    let secret = this.kvGet('secret');
    if (!secret) { secret = crypto.randomBytes(32).toString('hex'); this.kvSet('secret', secret); }
    this.secret = secret;
    // The db document: users, passkey creds, push subs, invites, device links. Only a missing
    // row starts empty — SQLite cannot hand back a torn write, so the .bak fallback the Node
    // server keeps is a file-filesystem problem this storage never had.
    const row = this.sql.exec(`SELECT value FROM docs WHERE key = 'db'`).toArray()[0];
    this.db = row ? this.parseDb(row.value) : { users: [], creds: [], subs: [], invites: [], deviceLinks: [] };
    this.auditSeq = this.sql.exec(`SELECT COALESCE(MAX(id), 0) AS n FROM audit`).toArray()[0]?.n || 0;
    // The AI Coach (workers/src/coach/) — configured through the admin dashboard, its
    // settings and per-user records in this same docs table, its scheduled reviews on the
    // alarm below. A job that was running when the object was evicted gets the honest answer
    // here, the same as the Node server's recoverOnBoot.
    this.coach = new Coach({
      sql: this.sql, env: this.env, secret,
      readState: uid => { const S = this.readStateStrict(uid); return S === UNREADABLE ? null : S; },
      listUserIds: () => this.sql.exec(`SELECT key FROM docs WHERE key LIKE 'state:%'`).toArray().map(r => r.key.slice(6)),
      waitUntil: p => this.ctx.waitUntil(p)
    });
    coachJobs.recoverStale(this.coach);
    Object.assign(this.routes, coachRoutes(this));
    // The cadence tick (a 60 s setInterval on the Node server) is the DO alarm: set if none
    // is pending, and re-armed from alarm() after every tick.
    if (await this.ctx.storage.getAlarm() == null) await this.ctx.storage.setAlarm(Date.now() + 60000);
  }

  /* The cadence tick: scheduled Coach reviews for every profile whose cadence came due.
   *  Everything else about the alarm is in coach/cadence.js; this only re-arms it. */
  async alarm() {
    await this.ready;
    try { await coachTick(this.coach, this.db.users); }
    catch (e) { console.error('coach cadence tick', e); }
    try { await this.ctx.storage.setAlarm(Date.now() + 60000); } catch { /* object shutting down */ }
  }
  parseDb(text) {
    const v = JSON.parse(text);
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('db document is not an object');
    v.users = v.users || []; v.creds = v.creds || []; v.subs = v.subs || [];
    v.invites = v.invites || []; v.deviceLinks = v.deviceLinks || [];
    return v;
  }
  saveDb() {
    this.sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES ('db', ?)`, JSON.stringify(this.db));
  }
  kvGet(key) {
    const row = this.sql.exec(`SELECT value, exp FROM kv WHERE key = ?`, key).toArray()[0];
    if (!row) return null;
    if (row.exp != null && row.exp < Date.now()) { this.sql.exec(`DELETE FROM kv WHERE key = ?`, key); return null; }
    return row.value;
  }
  kvSet(key, value, exp = null) {
    this.sql.exec(`INSERT OR REPLACE INTO kv (key, value, exp) VALUES (?, ?, ?)`, key, value, exp);
  }
  kvDel(key) { this.sql.exec(`DELETE FROM kv WHERE key = ?`, key); }

  /* ---------- per-profile state documents ---------- */
  stateKey(uid) { return 'state:' + uid.replace(/[^a-zA-Z0-9_-]/g, ''); }
  // null = no state yet; UNREADABLE = a document that cannot be parsed (answered 503, never
  // adopted empty). SQLite rows are written whole, so this is belt-and-braces against a
  // hand-imported bad document rather than the torn-file case it guards on disk.
  readStateStrict(uid) {
    const row = this.sql.exec(`SELECT value FROM docs WHERE key = ?`, this.stateKey(uid)).toArray()[0];
    if (!row) return null;
    try { return JSON.parse(row.value); } catch { return UNREADABLE; }
  }
  putState(uid, doc) {
    this.sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES (?, ?)`, this.stateKey(uid), JSON.stringify(doc));
  }

  /* ---------- sessions (signed cookie, stateless — same as api/server.js) ---------- */
  sign(payload) {
    const mac = crypto.createHmac('sha256', this.secret).update(payload).digest('base64url');
    return payload + '.' + mac;
  }
  verifySig(token) {
    const i = token.lastIndexOf('.');
    if (i < 0) return null;
    const payload = token.slice(0, i), mac = token.slice(i + 1);
    const expect = crypto.createHmac('sha256', this.secret).update(payload).digest('base64url');
    return timingSafeB64(mac, expect) ? payload : null;
  }
  sessionVersion(user) { return user.sv || 0; }
  makeSession(user) {
    return this.sign(user.id + ':' + (Date.now() + this.SESSION_DAYS * 86400000) + ':' + this.sessionVersion(user));
  }
  cookieNames() {
    const secure = this.SECURE;
    return secure ? ['__Host-gymsid', 'gymsid'] : ['gymsid'];
  }
  cookieToken(request) {
    for (const name of this.cookieNames()) {
      const vals = [];
      for (const c of (request.headers.get('cookie') || '').split(';')) {
        const i = c.indexOf('=');
        if (i >= 0 && c.slice(0, i).trim() === name) vals.push(c.slice(i + 1).trim());
      }
      if (!vals.length) continue;
      // Two different values under one name means somebody else got to set one; refuse both.
      if (vals.some(v => v !== vals[0])) return null;
      return vals[0];
    }
    return null;
  }
  sessionOf(request) {
    const auth = request.headers.get('authorization') || '';
    const cookie = this.cookieToken(request);
    const tok = cookie || (auth.startsWith('Bearer ') ? auth.slice(7).trim() : null);
    if (!tok) return null;
    const payload = this.verifySig(tok);
    if (!payload) return null;
    const [uid, exp, ver] = payload.split(':');
    if (!uid || +exp < Date.now()) return null;
    const user = this.db.users.find(u => u.id === uid) || null;
    if (!user || user.disabled) return null;
    const claimed = ver === undefined ? 0 : Number(ver);
    if (!Number.isInteger(claimed) || claimed !== this.sessionVersion(user)) return null;
    return { user, exp: +exp, bearer: !cookie };
  }
  readSession(request) { return this.sessionOf(request)?.user || null; }
  expireCookie(name) { return `${name}=; Path=/; Max-Age=0; HttpOnly;${this.SECURE} SameSite=Lax`; }
  sessionCookie(user) {
    const fresh = `${this.cookieNames()[0]}=${this.makeSession(user)}; Path=/; Max-Age=${this.SESSION_DAYS * 86400}; HttpOnly;${this.SECURE} SameSite=Lax`;
    const names = this.cookieNames();
    return [fresh, ...names.slice(1).map(n => this.expireCookie(n))];
  }
  clearCookie() { return this.cookieNames().map(n => this.expireCookie(n)); }

  /* ---------- CSRF (ported: same exemptions, same Sec-Fetch-Site logic) ---------- */
  csrfOk(request, key) {
    const method = request.method;
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true;
    if (CSRF_EXEMPT.has(key)) return true;
    if ((request.headers.get('authorization') || '').startsWith('Bearer ')) return true;
    const site = request.headers.get('sec-fetch-site');
    if (site) return site === 'same-origin' || site === 'none';
    const origin = request.headers.get('origin');
    if (!origin) return true;
    return origin.replace(/\/+$/, '') === this.ORIGIN.replace(/\/+$/, '');
  }

  /* ---------- challenges and pairings (5-minute, one-shot) ---------- */
  putChallenge(data) {
    // Expired rows go on the way in; nothing reads them often enough to sweep on a timer.
    this.sql.exec(`DELETE FROM kv WHERE exp IS NOT NULL AND exp < ?`, Date.now());
    const cid = crypto.randomBytes(16).toString('base64url');
    this.kvSet('ch:' + cid, JSON.stringify({ ...data, exp: Date.now() + 5 * MINUTE }), Date.now() + 5 * MINUTE);
    return cid;
  }
  takeChallenge(cid) {
    const raw = this.kvGet('ch:' + String(cid));
    if (raw == null) return null;
    this.kvDel('ch:' + String(cid));
    return JSON.parse(raw);
  }
  makePairCode() {
    const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no 0/O/1/I — read off a screen
    let code;
    do { code = Array.from(crypto.randomBytes(8)).map(b => A[b % A.length]).join(''); }
    while (this.kvGet('pair:' + code) != null);
    return code;
  }

  /* ---------- audit ---------- */
  // Which header holds the caller: on Workers it is always CF-Connecting-IP, set by the edge
  // and not forgeable by the client. Off unless AUDIT_IP asks for it — an IP says where
  // somebody physically is.
  clientIp(request) {
    const mode = String(this.env.AUDIT_IP || '').trim().toLowerCase();
    if (mode !== 'full' && mode !== 'net' && !ON.test(this.env.AUDIT_IP || '')) return null;
    const raw = String(request.headers.get('cf-connecting-ip') || '').trim();
    if (!raw) return null;
    const ip = raw.replace(/^\[|\]$/g, '').slice(0, 45);
    if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return null;
    if (mode === 'full') return ip;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.replace(/\.\d{1,3}$/, '.0/24');
    const g = ip.split(':').filter(Boolean).slice(0, 3).join(':');
    return g ? g + '::/48' : null;
  }
  limitAddress(request) {
    return this.clientIp(request) || 'local';
  }
  // Never throws: a log that cannot be written must not break signing in.
  audit(request, ev, f = {}) {
    if (!this.AUDIT_ON) return;
    const rec = { ts: Date.now(), ev, ok: f.ok !== false };
    if (f.user) { rec.uid = f.user.id; rec.name = String(f.user.name || '').slice(0, 40); }
    else { if (f.uid) rec.uid = f.uid; if (f.name) rec.name = String(f.name).slice(0, 40); }
    if (f.target) { rec.tgt = f.target.id; rec.tname = String(f.target.name || '').slice(0, 40); }
    if (f.msg) rec.msg = String(f.msg).slice(0, 120);
    if (f.act) rec.act = String(f.act).slice(0, 40);
    const ip = this.clientIp(request);
    if (ip) rec.ip = ip;
    try {
      this.sql.exec(`INSERT INTO audit (ts, ev, ok, uid, name, tgt, tname, msg, ip)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        rec.ts, rec.ev, rec.ok ? 1 : 0, rec.uid || null, rec.name || null,
        rec.tgt || null, rec.tname || null, rec.msg || null, rec.ip || null);
      this.auditSeq++;
      // Retention, amortized: age first, then the newest AUDIT_MAX rows.
      if (this.AUDIT_MAX && (this.auditSeq % 250) === 0) this.compactAudit();
    } catch (e) { console.error('audit write failed', e.message); }
  }
  compactAudit() {
    if (this.AUDIT_DAYS) this.sql.exec(`DELETE FROM audit WHERE ts < ?`, Date.now() - this.AUDIT_DAYS * 86400000);
    if (this.AUDIT_MAX) {
      const n = this.sql.exec(`SELECT COUNT(*) AS n FROM audit`).toArray()[0]?.n || 0;
      if (n > this.AUDIT_MAX) this.sql.exec(`DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?)`, this.AUDIT_MAX);
    }
  }
  // A failed ceremony is audited like any other, but only the first few per address and event
  // a minute — a flood of junk requests must not push every sign-in out of the log.
  auditFail(request, ev, f) {
    if (this.failAudit.take(ev + '|' + this.limitAddress(request)) || this.failAuditAll.take(ev)) return;
    this.audit(request, ev, f);
  }

  /* ---------- request plumbing ---------- */
  async fetch(request) {
    await this.ready;
    let url;
    try { url = new URL(request.url); } catch { return json(400, { error: 'bad request' }); }
    const key = request.method + ' ' + url.pathname;
    const handler = this.routes[key];
    if (!handler) return json(404, { error: 'not found' });
    if (!this.csrfOk(request, key)) {
      console.warn('refused cross-origin', key, 'origin=' + request.headers.get('origin'), 'expected=' + this.ORIGIN);
      return json(403, { error: 'cross-origin request refused' });
    }
    try {
      const res = await handler.call(this, request);
      // A handler that answers without reading the body (login/options, logout, …) leaves the
      // request stream unconsumed, which workerd logs as a stream error once the response goes
      // out. Drain it here — readBody marks the requests it already consumed.
      if (!request[READ]) { try { await request.arrayBuffer(); } catch { /* already gone */ } }
      return res;
    }
    catch (e) {
      if (e instanceof HttpError) return json(e.status, { error: e.message });
      console.error(key, e);
      return json(500, { error: 'server error' });
    }
  }

  routes = {
    /* The container healthcheck read the status only; here the probe is a real write. */
    'GET /api/health': async function () {
      let writable = true;
      try {
        this.sql.exec(`INSERT OR REPLACE INTO kv (key, value) VALUES ('health', '1')`);
        this.sql.exec(`DELETE FROM kv WHERE key = 'health'`);
      } catch { writable = false; }
      if (!writable) return json(503, { ok: false, writable: false });
      return json(200, { ok: true, users: this.db.users.length, writable: true });
    },

    /* Public config the login screen needs before anyone is signed in. */
    'GET /api/config': async function (request) {
      const lang = String(this.env.DEFAULT_LANG || '').trim();
      return json(200, {
        invite_only: this.INVITE_ONLY,
        allow_guest: this.ALLOW_GUEST,
        ...(lang && /^[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})?$/.test(lang) ? { default_lang: lang } : {}),
        // No media, no password login on this deployment — the blocks stay absent, which is
        // how the client knows those features do not exist here. The Coach block is whatever
        // the admin dashboard configured (null until it is switched on and connected);
        // Google sign-in is the one extra this deployment has over the Node server.
        ...(this.GOOGLE ? { google_login: true } : {}),
        ...(this.readSession(request) ? { coach: await this.coach.publicConfig() } : {})
      });
    },

    /* A paired phone's token is renewed past half its life (see api/server.js /api/me). */
    'GET /api/me': async function (request) {
      const s = this.sessionOf(request);
      if (!s) return json(401, { error: 'not signed in' });
      const { user } = s;
      const renew = s.bearer && s.exp - Date.now() < this.SESSION_DAYS * 86400000 / 2;
      return json(200, { user: { id: user.id, name: user.name, admin: this.isAdmin(user) }, ...(renew ? { token: this.makeSession(user) } : {}) });
    },

    /* Google sign-in — this deployment's own (the Node server has none of these routes).
       The standard OAuth code flow: /api/auth/google sends the browser to Google's consent
       screen with a one-shot state (putChallenge, the same 5-minute challenge the passkey
       ceremonies use), the callback swaps the code for tokens at Google's token endpoint over
       HTTPS, and the id_token's claims name the account. Google documents that an id_token
       taken straight from its token endpoint may be trusted as-is; the iss/aud/exp checks
       below are the belt on top of that. A first sign-in creates the profile (named from the
       Google account), the next ones find it by the Google account id (googleSub). */
    'GET /api/auth/google': async function () {
      if (!this.GOOGLE) return json(404, { error: 'not found' });
      const q = new URLSearchParams({
        client_id: this.env.GOOGLE_CLIENT_ID,
        redirect_uri: this.googleRedirect(),
        response_type: 'code',
        scope: 'openid email profile',
        state: this.putChallenge({ kind: 'google' }),
        prompt: 'select_account',
      });
      return new Response(null, { status: 302, headers: { Location: 'https://accounts.google.com/o/oauth2/v2/auth?' + q } });
    },

    'GET /api/auth/google/callback': async function (request) {
      if (!this.GOOGLE) return json(404, { error: 'not found' });
      const url = new URL(request.url);
      const code = url.searchParams.get('code') || '';
      const c = this.takeChallenge(url.searchParams.get('state') || '');
      // The failures land on a plain page, not JSON: this is a top-level navigation, the app
      // is not there to toast anything.
      const denied = (msg, status = 401) => new Response(
        '<!doctype html><meta charset="utf-8"><title>openGym</title>' +
        '<div style="font-family:system-ui;padding:2rem;line-height:1.6">' + msg +
        '<br><a href="/">&#8592; openGym</a></div>',
        { status, headers: [['Content-Type', 'text/html; charset=utf-8'], ['Cache-Control', 'no-store']] });
      if (url.searchParams.get('error') || !code || !c || c.kind !== 'google') {
        this.auditFail(request, 'auth.google.fail', { ok: false, msg: 'state-or-code' });
        return denied('That sign-in link is used, expired or incomplete. Go back and try again.');
      }
      let claims = null;
      try {
        const r = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: this.env.GOOGLE_CLIENT_ID,
            client_secret: this.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: this.googleRedirect(),
            grant_type: 'authorization_code',
          }),
        });
        claims = jwtClaims((await r.json()).id_token);
      } catch { claims = null; }
      const issOk = claims && (claims.iss === 'accounts.google.com' || claims.iss === 'https://accounts.google.com');
      if (!issOk || claims.aud !== this.env.GOOGLE_CLIENT_ID || !(claims.exp > Date.now() / 1000) || !claims.sub) {
        this.auditFail(request, 'auth.google.fail', { ok: false, msg: 'token' });
        return denied('Google&#8217;s answer could not be verified. Go back and try again.');
      }
      let user = this.db.users.find(u => u.googleSub === claims.sub);
      if (!user) {
        if (this.INVITE_ONLY) {
          this.audit(request, 'auth.google.denied', { ok: false, msg: 'invite-only' });
          return denied('This instance is invite-only; ask its admin for an invite.', 403);
        }
        user = {
          id: crypto.randomBytes(12).toString('base64url'),
          name: String(claims.name || String(claims.email || 'Google user').split('@')[0]).slice(0, 40),
          googleSub: claims.sub,
          created: new Date().toISOString(),
        };
        if (claims.email) user.email = String(claims.email).slice(0, 100);
        if (this.FIRST_USER_ADMIN && this.db.users.length === 0) user.admin = true;
        this.db.users.push(user);
        this.saveDb();
        this.audit(request, 'auth.google.register', { user });
      } else {
        this.audit(request, 'auth.google.login', { user });
      }
      const headers = new Headers({ Location: this.ORIGIN.replace(/\/+$/, '') + '/' });
      for (const cookie of this.sessionCookie(user)) headers.append('Set-Cookie', cookie);
      return new Response(null, { status: 302, headers });
    },

    'POST /api/register/options': async function (request) {
      const body = await readBody(request);
      const name = text(body.name).trim().slice(0, 40);
      if (!name) return json(400, { error: 'name required' });
      const code = text(body.code).trim().toUpperCase();
      if (this.INVITE_ONLY && !this.db.invites.some(i => i.code === code && !i.usedBy && !i.revoked)) {
        this.audit(request, 'auth.register.denied', { ok: false, name, msg: 'invite-rejected' });
        return json(403, { error: 'a valid invite code is required', code: 'invite' });
      }
      const uid = crypto.randomBytes(12).toString('base64url');
      const options = await generateRegistrationOptions({
        rpName: this.RP_NAME, rpID: this.RP_ID,
        userID: Buffer.from(uid), userName: name, userDisplayName: name,
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
        excludeCredentials: []
      });
      const cid = this.putChallenge({ kind: 'register', challenge: options.challenge, name, uid, code });
      return json(200, { cid, options });
    },

    'POST /api/register/verify': async function (request) {
      const body = await readBody(request);
      const c = this.takeChallenge(body.cid);
      if (!c || c.kind !== 'register' || !c.uid) {
        this.auditFail(request, 'auth.register.fail', { ok: false, msg: 'challenge-expired' });
        return json(400, { error: 'challenge expired, try again', code: 'challenge-expired' });
      }
      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: body.credential,
          expectedChallenge: c.challenge,
          expectedOrigin: this.ORIGIN,
          expectedRPID: this.RP_ID,
          requireUserVerification: false
        });
      } catch (e) {
        this.auditFail(request, 'auth.register.fail', { ok: false, name: c.name, msg: 'verify-error' });
        return json(400, { error: verifyError(e, { rpId: this.RP_ID, origin: this.ORIGIN }) });
      }
      if (!verification.verified) {
        this.auditFail(request, 'auth.register.fail', { ok: false, name: c.name, msg: 'not-verified' });
        return json(400, { error: 'not verified' });
      }
      const { credential } = verification.registrationInfo;
      if (this.db.creds.find(x => x.id === credential.id)) {
        this.audit(request, 'auth.register.fail', { ok: false, name: c.name, msg: 'credential-exists' });
        return json(409, { error: 'credential already registered' });
      }
      // Re-check the invite at the last moment (it may have been used/revoked since options), then burn it.
      let invite = null;
      if (this.INVITE_ONLY) {
        invite = this.db.invites.find(i => i.code === c.code && !i.usedBy && !i.revoked);
        if (!invite) {
          this.audit(request, 'auth.register.fail', { ok: false, name: c.name, msg: 'invite-invalid' });
          return json(403, { error: 'invite code is no longer valid, ask for a new one', code: 'invite' });
        }
      }
      const user = { id: c.uid, name: c.name, created: new Date().toISOString() };
      if (invite) { user.invitedBy = invite.code; invite.usedBy = user.id; invite.usedAt = user.created; }
      if (this.FIRST_USER_ADMIN && this.db.users.length === 0) user.admin = true;
      this.db.users.push(user);
      this.db.creds.push({
        id: credential.id, userId: user.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter || 0,
        transports: body.credential?.response?.transports || [],
        created: user.created, lastUsed: user.created
      });
      this.saveDb();
      this.audit(request, 'auth.register.ok', { user, msg: invite ? invite.code : null });
      return json(200, { user: { id: user.id, name: user.name, admin: this.isAdmin(user) } }, this.sessionCookie(user));
    },

    'POST /api/login/options': async function () {
      const options = await generateAuthenticationOptions({
        rpID: this.RP_ID, userVerification: 'preferred', allowCredentials: []
      });
      const cid = this.putChallenge({ kind: 'login', challenge: options.challenge });
      return json(200, { cid, options });
    },

    'POST /api/login/verify': async function (request) {
      const body = await readBody(request);
      const c = this.takeChallenge(body.cid);
      if (c?.kind !== 'login') {
        this.auditFail(request, 'auth.login.fail', { ok: false, msg: 'challenge-expired' });
        return json(400, { error: 'challenge expired, try again', code: 'challenge-expired' });
      }
      const cred = this.db.creds.find(x => x.id === body.credential?.id);
      if (!cred) {
        this.auditFail(request, 'auth.login.fail', { ok: false, msg: 'unknown-credential' });
        return json(404, { error: 'unknown passkey, create a profile first', code: 'unknown-credential' });
      }
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: body.credential,
          expectedChallenge: c.challenge,
          expectedOrigin: this.ORIGIN,
          expectedRPID: this.RP_ID,
          requireUserVerification: false,
          credential: {
            id: cred.id,
            publicKey: b64uToBuf(cred.publicKey),
            counter: cred.counter,
            transports: cred.transports
          }
        });
      } catch (e) {
        this.auditFail(request, 'auth.login.fail', { ok: false, user: this.db.users.find(u => u.id === cred.userId), uid: cred.userId, msg: 'verify-error' });
        return json(400, { error: verifyError(e, { rpId: this.RP_ID, origin: this.ORIGIN }) });
      }
      if (!verification.verified) {
        this.auditFail(request, 'auth.login.fail', { ok: false, user: this.db.users.find(u => u.id === cred.userId), uid: cred.userId, msg: 'not-verified' });
        return json(400, { error: 'not verified' });
      }
      cred.counter = verification.authenticationInfo.newCounter;
      cred.lastUsed = new Date().toISOString();
      this.saveDb();
      const user = this.db.users.find(u => u.id === cred.userId);
      if (!user) {
        this.audit(request, 'auth.login.fail', { ok: false, uid: cred.userId, msg: 'user-missing' });
        return json(500, { error: 'user missing' });
      }
      if (user.disabled) {
        this.audit(request, 'auth.login.fail', { ok: false, user, msg: 'account-disabled' });
        return json(403, { error: 'this account has been disabled', code: 'disabled' });
      }
      this.audit(request, 'auth.login.ok', { user });
      return json(200, { user: { id: user.id, name: user.name, admin: this.isAdmin(user) } }, this.sessionCookie(user));
    },

    'POST /api/logout': async function (request) {
      const user = this.readSession(request);
      if (user) this.audit(request, 'auth.logout', { user });
      return json(200, { ok: true }, this.clearCookie());
    },

    /* "Sign out everywhere" — bumps the session version, invalidating every cookie ever
       issued for the account, and takes the pairing codes and device links with it. */
    'POST /api/logout/all': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      user.sv = this.sessionVersion(user) + 1;
      for (const row of this.sql.exec(`SELECT key FROM kv WHERE key LIKE 'pair:%'`).toArray()) this.kvDel(row.key);
      dropDeviceLinks(this.db, user.id);
      this.saveDb();
      this.audit(request, 'auth.logout.all', { user });
      return json(200, { ok: true }, this.clearCookie());
    },

    /* Mobile app pairing: a short code minted from a signed-in browser tab. */
    'POST /api/pair/create': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      // One live code per profile: the newest is the one on screen.
      for (const row of this.sql.exec(`SELECT key, value FROM kv WHERE key LIKE 'pair:%'`).toArray()) {
        try { if (JSON.parse(row.value).uid === user.id) this.kvDel(row.key); } catch { this.kvDel(row.key); }
      }
      const code = this.makePairCode();
      this.kvSet('pair:' + code, JSON.stringify({ uid: user.id }), Date.now() + 5 * MINUTE);
      this.audit(request, 'auth.pair.create', { user });
      return json(200, { code });
    },

    'POST /api/pair/redeem': async function (request) {
      const body = await readBody(request);
      const code = text(body.code).trim().toUpperCase();
      const raw = this.kvGet('pair:' + code);
      if (raw != null) this.kvDel('pair:' + code);
      const p = raw != null ? JSON.parse(raw) : null;
      if (!p || !p.uid) {
        this.auditFail(request, 'auth.pair.fail', { ok: false, msg: 'code-invalid' });
        return json(400, { error: 'invalid or expired code', code: 'pair-invalid' });
      }
      const user = this.db.users.find(u => u.id === p.uid);
      if (!user || user.disabled) {
        this.audit(request, 'auth.pair.fail', { ok: false, uid: p.uid, msg: 'user-unavailable' });
        return json(400, { error: 'invalid or expired code', code: 'pair-invalid' });
      }
      this.audit(request, 'auth.pair.ok', { user });
      return json(200, { token: this.makeSession(user), user: { id: user.id, name: user.name, admin: this.isAdmin(user) } });
    },

    /* ---------- sync (the heart of the app) ---------- */

    'GET /api/data': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const state = this.readStateStrict(user.id);
      if (state === UNREADABLE) return json(503, { error: 'state unreadable' });
      this.notePull(user);
      return json(200, { state: forClient(state), rev: state?._rev || 0 });
    },

    'GET /api/data/rev': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const doc = this.readStateStrict(user.id);
      if (doc === UNREADABLE) return json(503, { error: 'state unreadable' });
      return json(200, { rev: doc?._rev || 0, ...(doc?._wid ? { wid: doc._wid } : {}) });
    },

    'PUT /api/data': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      if (!body.state || typeof body.state !== 'object') return json(400, { error: 'state required' });
      // An object with nothing of the profile in it empties the document with the counter
      // left intact — refused, as in api/server.js.
      if (!Array.isArray(body.state) && !Object.keys(body.state).some(k => k !== '_rev' && k !== '_ts')) {
        return json(400, { error: 'state required' });
      }
      const list = v => v == null || Array.isArray(v);
      if (Array.isArray(body.state) || !list(body.state.workouts) || !list(body.state.routines)) return json(400, { error: 'invalid state' });
      for (const k of ['workouts', 'routines']) if (Array.isArray(body.state[k])) body.state[k] = records(body.state[k]);
      const cur = this.readStateStrict(user.id);
      if (cur === UNREADABLE) return json(503, { error: 'state unreadable' });
      const curRev = cur?._rev || 0;
      // Conditional write: a baseRev/baseWid that is not the current document means another
      // device wrote since — the current document travels back with the 409 to merge.
      if ((body.baseRev != null && body.baseRev !== curRev) ||
          (body.baseRev != null && typeof body.baseWid === 'string' && cur?._wid && body.baseWid !== cur._wid)) {
        return json(409, { error: 'conflict', rev: curRev, state: forClient(cur) });
      }
      delete body.state.active;              // in-progress workouts stay device-local
      // "Reset everything" stamps only move forward (see api/server.js).
      const storedReset = Number(cur?.resetAt) || 0;
      if (storedReset > (Number(body.state.resetAt) || 0)) {
        body.state.resetAt = cur.resetAt;
        if (cur.resetIds && typeof cur.resetIds === 'object') body.state.resetIds = cur.resetIds;
        else delete body.state.resetIds;
      }
      const report = {};
      try { stampPut(cur, body.state, { overRead: body.baseRev != null && body.baseRev === curRev, stamped: body.stamped === true, report }); }
      catch (e) { if (e instanceof RangeError) return json(400, { error: 'invalid state' }); throw e; }
      body.state._rev = curRev + 1;
      if (report.changed) body.state._rev = curRev + 2;
      body.state._wids = [...(Array.isArray(cur?._wids) ? cur._wids : []), ...(cur?._wid ? [cur._wid] : [])]
        .filter(x => typeof x === 'string').slice(-WID_KEEP);
      body.state._wid = crypto.randomBytes(8).toString('hex');
      let text;
      try { text = JSON.stringify(body.state); }
      catch (e) { if (e instanceof RangeError) return json(400, { error: 'invalid state' }); throw e; }
      this.putState(user.id, body.state);
      return json(200, { ok: true, ts: body.state._ts || null, rev: curRev + 1, wid: body.state._wid });
    },

    /* Live presence — a heartbeat the (not yet ported) admin dashboard reads. Ephemeral,
       never persisted, exactly as in the Node server. */
    'POST /api/activity': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      if (body.active) {
        this.presence.set(user.id, {
          name: text(body.name).slice(0, 60),
          exIdx: +body.exIdx || 0, exTotal: +body.exTotal || 0,
          setsDone: +body.setsDone || 0, setsTotal: +body.setsTotal || 0,
          startedAt: +body.startedAt || Date.now(), updatedAt: Date.now()
        });
      } else if (body.reason === 'hidden') {
        const p = this.presence.get(user.id);
        if (p && p.hiddenAt === undefined) p.hiddenAt = Date.now();
      } else this.presence.delete(user.id);
      return json(200, { ok: true });
    },

    /* ---------- Settings → Passkeys, and device links (#95) ---------- */

    'GET /api/account/passkeys': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      return json(200, this.passkeyState(user));
    },

    // Adding one from Settings, step one: the proof, then the options. The proof is spent here;
    // the challenge that comes back is good for five minutes, for this profile, under this
    // session version — "sign out everywhere" in between ends the ceremony with everything else.
    'POST /api/account/passkeys/options': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      if (this.passkeyCount(user) >= MAX_PASSKEYS) return json(409, LIMIT);
      const proof = await this.proveOwner(request, user, body, 'passkey-add');
      if (proof.answer) return proof.answer;
      if (this.readSession(request) !== user) return json(401, { error: 'not signed in' });
      if (proof === 'passkey') this.saveDb();   // the confirming passkey's counter and last use
      const options = await this.moreOptions(user);
      const cid = this.putChallenge({ challenge: options.challenge, uid: user.id, kind: 'add', sv: this.sessionVersion(user), proof });
      return json(200, { cid, options });
    },

    'POST /api/account/passkeys/verify': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      const c = this.takeChallenge(text(body.cid));
      if (!c || c.kind !== 'add' || c.uid !== user.id) {
        this.audit(request, 'auth.passkey.fail', { ok: false, user, msg: 'challenge-expired' });
        return json(400, { error: 'challenge expired, try again', code: 'challenge-expired' });
      }
      const made = await this.newPasskey(request, c, body, 'auth.passkey.fail', user);
      if (made.answer) return made.answer;
      if (this.readSession(request) !== user || this.sessionVersion(user) !== c.sv) return json(401, { error: 'not signed in' });
      const added = addPasskeyRecord(this.db, user.id, made.cred);
      if (added.error) {
        this.audit(request, 'auth.passkey.fail', { ok: false, user, msg: added.code });
        return json(409, { error: added.error, code: added.code });
      }
      this.saveDb();
      this.audit(request, 'auth.passkey.add', { user, msg: c.proof });
      return json(200, { ok: true, ...this.passkeyState(user) });
    },

    'POST /api/account/passkeys/rename': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      const r = renamePasskeyRecord(this.db, user.id, text(body.id), body.name);
      if (r.error) return json(404, { error: r.error, code: r.code });
      this.saveDb();
      return json(200, { ok: true, ...this.passkeyState(user) });
    },

    // `?id=` — the credential id from the list; the body carries the same proof adding one takes,
    // asked only once the removal could go ahead. The last one is never removed, checked again
    // after the proof. An unused device code goes with it: a passkey is removed because it is
    // lost or not trusted, and a code made with it just before would add a fresh one right after.
    'DELETE /api/account/passkeys': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const id = new URL(request.url).searchParams.get('id') || '';
      const body = await readBody(request);
      const refuse = r => json(r.code === 'last-way-in' ? 409 : 404, { error: r.error, code: r.code });
      const refused = passkeyRemovalRefused(this.db, user.id, id, 0);
      if (refused) return refuse(refused);
      const proof = await this.proveOwner(request, user, body, 'passkey-remove');
      if (proof.answer) return proof.answer;
      if (this.readSession(request) !== user) return json(401, { error: 'not signed in' });
      if (proof === 'passkey') this.saveDb();   // the confirming passkey's counter and last use
      const r = removePasskeyRecord(this.db, user.id, id, 0);
      if (r.error) return refuse(r);
      dropDeviceLinks(this.db, user.id);
      this.saveDb();
      this.audit(request, 'auth.passkey.remove', { user, msg: r.row.name || null });
      return json(200, { ok: true, ...this.passkeyState(user) });
    },

    // Makes the code another device redeems below. Same proof as adding a passkey here, because
    // the code is how a passkey gets added there.
    'POST /api/account/device-link': async function (request) {
      const user = this.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await readBody(request);
      if (this.passkeyCount(user) >= MAX_PASSKEYS) return json(409, LIMIT);
      const proof = await this.proveOwner(request, user, body, 'device-link');
      if (proof.answer) return proof.answer;
      if (this.readSession(request) !== user) return json(401, { error: 'not signed in' });
      const { code, link } = createDeviceLink(this.db, user.id);
      this.saveDb();
      this.audit(request, 'auth.link.create', { user, msg: proof });
      return json(200, { code, expires: link.exp });
    },

    // Redeeming, from the other device, which has no session: the code is the credential. Step
    // one checks it and hands back creation options for the profile it belongs to, and that
    // profile's name and id, so the screen can say where this device is being added. It does not
    // use the code up — a passkey prompt dismissed by mistake can be tried again — and wrong
    // codes pause the address.
    'POST /api/device-link/options': async function (request) {
      const body = await readBody(request);
      const paused = this.addressPaused(request, 'link');
      if (paused) return paused;
      const link = findDeviceLink(this.db, text(body.code));
      if (!link) {
        this.strikeAddress(request, 'link');
        this.audit(request, 'auth.link.fail', { ok: false, msg: 'link-invalid' });
        return json(400, LINK_INVALID);
      }
      const user = this.db.users.find(u => u.id === link.userId);
      if (!user || user.disabled) {
        this.audit(request, 'auth.link.fail', { ok: false, uid: link.userId, msg: 'user-unavailable' });
        return json(400, LINK_INVALID);
      }
      if (this.passkeyCount(user) >= MAX_PASSKEYS) return json(409, LIMIT);
      const options = await this.moreOptions(user);
      const cid = this.putChallenge({ challenge: options.challenge, uid: user.id, kind: 'link', lh: link.h });
      return json(200, { cid, options, id: user.id, name: user.name });
    },

    // Step two: the new passkey is stored, the code is burned, and this device is signed in by
    // the passkey it just made — the same cookie a passkey sign-in sets.
    'POST /api/device-link/verify': async function (request) {
      const body = await readBody(request);
      const paused = this.addressPaused(request, 'link');
      if (paused) return paused;
      const code = text(body.code);
      const c = this.takeChallenge(text(body.cid));
      const link = findDeviceLink(this.db, code);
      if (!link) {
        this.strikeAddress(request, 'link');
        this.audit(request, 'auth.link.fail', { ok: false, msg: 'link-invalid' });
        return json(400, LINK_INVALID);
      }
      if (!c || c.kind !== 'link' || c.lh !== link.h || c.uid !== link.userId) {
        this.audit(request, 'auth.link.fail', { ok: false, uid: link.userId, msg: 'challenge-expired' });
        return json(400, { error: 'challenge expired, try again', code: 'challenge-expired' });
      }
      const owner = this.db.users.find(u => u.id === link.userId);
      const made = await this.newPasskey(request, c, body, 'auth.link.fail', owner || { id: link.userId });
      if (made.answer) return made.answer;
      // Everything above awaited: the code may have been used, replaced or dropped since, and
      // the profile may be gone or locked.
      const user = this.db.users.find(u => u.id === link.userId);
      if (findDeviceLink(this.db, code) !== link || !user || user.disabled) {
        this.audit(request, 'auth.link.fail', { ok: false, uid: link.userId, msg: 'link-invalid' });
        return json(400, LINK_INVALID);
      }
      const added = addPasskeyRecord(this.db, user.id, made.cred);
      if (added.error) {
        this.audit(request, 'auth.link.fail', { ok: false, user, msg: added.code });
        return json(409, { error: added.error, code: added.code });
      }
      added.row.lastUsed = added.row.created;
      burnDeviceLink(this.db, link);
      this.saveDb();
      this.audit(request, 'auth.link.ok', { user, msg: added.row.name || null });
      return json(200, { user: { id: user.id, name: user.name, admin: this.isAdmin(user) } }, this.sessionCookie(user));
    }
  };

  isAdmin(user) { return !!user && (user.admin === true || this.ADMIN_UIDS.includes(user.id)); }

  /* ---------- passkey bookkeeping (Settings → Passkeys, device links) ---------- */
  passkeyCount(user) { return this.db.creds.filter(c => c.userId === user.id).length; }
  // `password`: whether a password could confirm an addition/removal — never here, this
  // deployment has no password routes. `lastWayIn`: whether removing any one passkey is refused.
  passkeyState(user) {
    const passkeys = listPasskeys(this.db, user.id);
    return { passkeys, password: false, lastWayIn: passkeys.length + 0 <= 1 };
  }
  // Creation options for another passkey of `user`: same user handle as at sign-up, the
  // passkeys the profile already has excluded.
  async moreOptions(user) {
    return generateRegistrationOptions({
      rpName: this.RP_NAME, rpID: this.RP_ID,
      userID: Buffer.from(user.id), userName: user.name, userDisplayName: user.name,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: this.db.creds.filter(c => c.userId === user.id).map(c => ({ id: c.id, transports: c.transports || [] }))
    });
  }
  // The second half of either ceremony: the new passkey as a creds row, or null once the
  // refusal has been answered and audited as `ev`.
  async newPasskey(request, c, body, ev, user) {
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.credential, expectedChallenge: c.challenge,
        expectedOrigin: this.ORIGIN, expectedRPID: this.RP_ID, requireUserVerification: false
      });
    } catch (e) {
      this.audit(request, ev, { ok: false, user, msg: 'verify-error' });
      return { answer: json(400, { error: verifyError(e, { rpId: this.RP_ID, origin: this.ORIGIN }) }) };
    }
    if (!verification.verified) {
      this.audit(request, ev, { ok: false, user, msg: 'not-verified' });
      return { answer: json(400, { error: 'not verified' }) };
    }
    const { credential } = verification.registrationInfo;
    return {
      cred: {
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter || 0,
        transports: body.credential?.response?.transports,
        name: body.name
      }
    };
  }
  // A passkey assertion made just now by the signed-in account itself — how someone proves it
  // is them before adding a passkey or making a device link. A session alone is not enough: it
  // may be a cookie someone walked off with. Same ceremony as /api/login/verify, and the
  // credential has to belong to this account.
  async passkeyStepUp(user, body) {
    const c = this.takeChallenge(body.cid);
    const cred = c?.kind === 'login' && this.db.creds.find(x => x.id === body.credential?.id && x.userId === user.id);
    if (!cred) return false;
    try {
      const v = await verifyAuthenticationResponse({
        response: body.credential, expectedChallenge: c.challenge,
        expectedOrigin: this.ORIGIN, expectedRPID: this.RP_ID, requireUserVerification: false,
        credential: { id: cred.id, publicKey: b64uToBuf(cred.publicKey), counter: cred.counter, transports: cred.transports }
      });
      if (!v.verified) return false;
      cred.counter = v.authenticationInfo.newCounter;
      cred.lastUsed = new Date().toISOString();
      return true;
    } catch { return false; }
  }
  // The proof an account-changing action asks for. No password routes on this deployment, so
  // the proof is always a passkey step-up; without one the caller is told to confirm with
  // their passkey first.
  async proveOwner(request, user, body, act) {
    if (body.credential) {
      if (await this.passkeyStepUp(user, body)) return 'passkey';
      this.audit(request, 'auth.proof.fail', { ok: false, user, msg: 'step-up-failed', act });
      return { answer: json(403, { error: 'the passkey could not be verified', code: 'passkey' }) };
    }
    return { answer: json(403, { error: 'confirm with your passkey first', code: 'passkey-required' }) };
  }
  /* ---------- the device-link throttle ---------- */
  limitAddress(request) {
    // On Workers CF-Connecting-IP is set by the edge and cannot be forged; an IPv6 client is
    // counted by its /64, which is what one household or one VPS is handed.
    const raw = String(request.headers.get('cf-connecting-ip') || '').replace(/^\[|\]$/g, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) return raw;
    if (raw.includes(':')) return raw.split(':').slice(0, 4).join(':') + '::/64';
    return 'local';
  }
  tooMany(secs) {
    return json(429, { error: 'too many attempts, try again later', code: 'locked', retryAfter: secs }, [['Retry-After', String(secs)]]);
  }
  addressPaused(request, kind) {
    const wait = this.addrFails.retryAfter(kind + '|' + this.limitAddress(request));
    return wait > 0 ? this.tooMany(wait) : null;
  }
  strikeAddress(request, kind) {
    const lock = this.addrFails.fail(kind + '|' + this.limitAddress(request));
    if (lock) this.audit(request, 'auth.throttled', { ok: false, msg: kind });
  }
  // When a profile last fetched its document; at most every ten minutes, since every
  // foreground return pulls.
  notePull(user, now = Date.now()) {
    if (user.lastPull && now - user.lastPull < PULL_NOTE_MS) return;
    user.lastPull = now;
    this.saveDb();
  }
}

/* ---------- helpers (module scope: no per-request state) ---------- */

const UNREADABLE = Symbol('unreadable');
// Marks a request whose body readBody consumed (see Db.fetch's drain).
const READ = Symbol('read');

const CSRF_EXEMPT = new Set([
  'POST /api/register/options', 'POST /api/register/verify',
  'POST /api/login/options', 'POST /api/login/verify',
  'POST /api/pair/redeem'
]);

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(status, obj, extra) {
  const headers = [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']];
  // A string is a Set-Cookie value; an array is a [name, value] pair.
  for (const c of extra || []) headers.push(typeof c === 'string' ? ['Set-Cookie', c] : c);
  return new Response(JSON.stringify(obj), { status, headers });
}

const LIMIT = { error: `a profile can have at most ${MAX_PASSKEYS} passkeys`, code: 'passkey-limit' };
const LINK_INVALID = { error: 'that code is wrong, used or expired', code: 'link-invalid' };

async function readBody(request) {
  request[READ] = true;
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_BODY) throw new HttpError(413, 'body too large');
  if (!buf.byteLength) return {};
  let body;
  try { body = JSON.parse(new TextDecoder().decode(buf)); }
  catch { throw new HttpError(400, 'invalid json'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'invalid json');
  return body;
}

const text = v => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');
const b64uToBuf = s => Buffer.from(s, 'base64url');
const record = x => !!x && typeof x === 'object' && !Array.isArray(x);
const records = v => (Array.isArray(v) ? v.filter(record) : []);

// A stored document as a client gets it: without the server's own notes `_unstamped` and `_prior`.
function forClient(S) {
  if (!S || typeof S !== 'object' || !('_unstamped' in S || '_prior' in S)) return S;
  const { _unstamped, _prior, ...rest } = S;
  return rest;
}

// Constant-time compare of two base64url strings (crypto.timingSafeEqual needs equal-length
// Buffers and throws otherwise; this is the same refusal, without the length leak).
function timingSafeB64(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// The claims of a JWT, decoded without any signature check — used only on the id_token that
// came straight from Google's own token endpoint over HTTPS (see the route comment).
function jwtClaims(jwt) {
  try { return JSON.parse(new TextDecoder().decode(b64uToBuf(String(jwt).split('.')[1]))); }
  catch { return null; }
}
