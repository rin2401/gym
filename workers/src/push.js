/* Web Push on the Worker — the port of the push half of api/server.js.
 *
 * The Node server leans on the `web-push` package; a Worker cannot (it drives node:crypto's
 * createSign/Agent/BlockList, none of which workerd implements), so the two RFCs the
 * protocol is made of are implemented here on WebCrypto:
 *
 *   RFC 8292 (VAPID) — an ES256 JWT proving who is sending, signed with an instance
 *     keypair generated on first use and kept in the kv table ('vapid'), the same
 *     lifecycle data/vapid.json has on the Node server.
 *   RFC 8291 (aes128gcm) — the payload encrypted to the subscription's own keys with an
 *     ephemeral ECDH pair, HKDF-derived CEK/nonce, AES-128-GCM.
 *
 * What else differs:
 *   - the SSRF posture is simpler: a Worker's fetch cannot reach the private networks the
 *     Node guard exists for (its container sits on the self-hoster's Docker network; the
 *     edge does not), so the guard keeps only the checks that still mean something —
 *     https, no credentials, no literal private address in the endpoint.
 *   - the reminder/nudge tick is the DO alarm (60 s; the window is 15 min), not a 10 s
 *     setInterval — the same "due is due for a while" catch-up idea, coarser.
 *   - rest timers are in-memory setTimeout on the DO, exactly the "an API restart drops
 *     whatever is pending" semantics the Node server documents for them.
 */
import { dayReminderPush, nudgePush, restTimerPush, testPush } from './push-messages.js';
import { effectiveRoutineId } from './queue.js';
import { nudgeFor, nudgeWindowOpen, excusedOn, toneOf } from './nudge.js';
import { userNow } from './coach/cadence.js';

const MAX_SUBS_PER_USER = 20;
const PUSH_TIMEOUT_MS = 10000;
const TTL_SEC = 86400 * 30;        // the web-push default: long, so a briefly-offline device still gets it
const REMINDER_WINDOW_MIN = 15;

const b64u = buf => Buffer.from(buf).toString('base64url');
const unb64u = s => new Uint8Array(Buffer.from(String(s || ''), 'base64url'));
const enc = new TextEncoder();

/* ---------- VAPID keypair (one per instance, kv 'vapid') ---------- */

/* ---------- RFC 8292: the VAPID Authorization header ---------- */

async function vapidHeader(db, endpoint) {
  const { publicKey, privateKey } = await vapidKeys(db);
  const aud = new URL(endpoint).origin;
  const header = b64u(enc.encode(JSON.stringify({ alg: 'ES256', typ: 'JWT' })));
  const payload = b64u(enc.encode(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: db.VAPID_SUBJECT
  })));
  // ES256's JOSE signature is raw r||s — exactly what WebCrypto produces.
  const key = await crypto.subtle.importKey('jwk', {
    kty: 'EC', crv: 'P-256',
    d: privateKey,
    x: b64u(unb64u(publicKey).subarray(1, 33)),
    y: b64u(unb64u(publicKey).subarray(33))
  }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign({ hash: 'SHA-256' }, key, enc.encode(header + '.' + payload)));
  return `vapid t=${header}.${payload}.${sig}, k=${publicKey}`;
}

/* ---------- RFC 8291: aes128gcm payload encryption ---------- */

const hkdf = async (salt, ikm, info, len) => {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, key, len * 8));
};

async function encryptPayload(keys, payload) {
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));   // 65 B, 0x04 || x || y
  const subscriber = await crypto.subtle.importKey('raw', unb64u(keys.p256dh), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const uaShared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: subscriber }, as.privateKey, 256));
  const auth = unb64u(keys.auth);
  // RFC 8291 §3: PRK over the shared secret salted with auth || as_public, then the CEK and
  // the nonce expanded from it with their own info strings (each 0x00-terminated).
  const salt = new Uint8Array([...auth, ...asPublic]);
  const ikmKey = await crypto.subtle.importKey('raw', uaShared, 'HKDF', false, ['deriveBits']);
  const prk = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('WebPush: aes128gcm\0') }, ikmKey, 256));
  const cek = await hkdf(prk, new Uint8Array(1), 'Content-Encoding: aes128gcm\0', 16);
  const nonce = await hkdf(prk, new Uint8Array([1]), 'Content-Encoding: nonce\0', 12);
  // aes128gcm padding: the plaintext delimited by 0x02, no padding records.
  const plaintext = new Uint8Array([...enc.encode(JSON.stringify(payload)), 2]);
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, plaintext));
  const saltRandom = crypto.getRandomValues(new Uint8Array(16));
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096);
  const idlen = new Uint8Array([asPublic.length]);
  return new Uint8Array([...saltRandom, ...rs, ...idlen, ...asPublic, ...ciphertext]);
}

/* ---------- the endpoint guard (the part of server.js's that still applies) ---------- */

function isPrivateV4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [+m[1], +m[2]];
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
/** Cheap pre-check so a bad endpoint is refused at subscribe time with a useful message, and
 *  re-judged before every send. A Worker's fetch cannot reach the private networks the Node
 *  guard's DNS-rebinding half exists for, so the literal-address check is the whole guard. */
export function pushEndpointError(raw) {
  let u;
  try { u = new URL(String(raw || '')); } catch { return 'endpoint is not a valid URL'; }
  if (u.protocol !== 'https:') return 'endpoint must be an https:// URL';
  if (u.username || u.password) return 'endpoint must not carry credentials';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (/^[0-9.]+$/.test(host) && isPrivateV4(host)) return 'endpoint must not point at a private address';
  if (host.includes(':') && (/^f[cd]/i.test(host.replace(/[^0-9a-f:]/gi, '').replace(/::.*$/, '')) || host === '::1' || host === '::')) {
    return 'endpoint must not point at a private address';
  }
  return null;
}

/* ---------- VAPID keys (kv 'vapid', generated on first use) ---------- */

async function vapidKeys(db) {
  if (db.vapid) return db.vapid;
  let v = null;
  try { const raw = db.kvGet('vapid'); if (raw) v = JSON.parse(raw); } catch { /* regenerate */ }
  if (!v || !v.publicKey || !v.privateKey) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    v = { publicKey: b64u(raw), privateKey: jwk.d };
    db.kvSet('vapid', JSON.stringify(v));
  }
  db.vapid = v;
  return v;
}

/* ---------- sending ---------- */

/** `deviceId` narrows the send to the subscriptions one browser registered (the rest-timer
 *  alert belongs to the device that started the rest, #348); a subscription stored without one
 *  still gets everything, as before. Prunes on 404/410/403 — the push service saying the
 *  subscription is gone, or refusing our VAPID signature (a subscription made against a key
 *  this instance no longer has). Neither will ever deliver again. */
export async function sendPush(db, userId, payload, deviceId) {
  let subs = db.db.subs.filter(s => s.userId === userId);
  if (deviceId) subs = subs.filter(s => !s.deviceId || s.deviceId === deviceId);
  if (!subs.length) return;
  const body = await encryptPayloadFor(db, subs, payload);
  let dirty = false;
  await Promise.all(subs.map(async sub => {
    const bad = pushEndpointError(sub.endpoint);
    if (bad) {
      console.error('push endpoint refused', userId, bad);
      db.db.subs = db.db.subs.filter(s => s.endpoint !== sub.endpoint); dirty = true;
      return;
    }
    // urgency 'high' is the one lever we have over delivery speed — iOS/Android throttle
    // low-urgency background push more aggressively under battery-saving modes.
    try {
      const r = await fetch(sub.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': 'aes128gcm',
          TTL: String(TTL_SEC),
          Urgency: 'high',
          Authorization: await vapidHeader(db, sub.endpoint)
        },
        body: body.get(sub.endpoint),
        signal: AbortSignal.timeout(PUSH_TIMEOUT_MS)
      });
      if (r.status === 404 || r.status === 410 || r.status === 403) {
        console.error('push send failed', userId, r.status);
        db.db.subs = db.db.subs.filter(s => s.endpoint !== sub.endpoint); dirty = true;
      } else if (!r.ok) {
        console.error('push send failed', userId, r.status, (await r.text()).slice(0, 120));
      }
    } catch (e) {
      console.error('push send failed', userId, e.message);
    }
  }));
  if (dirty) db.saveDb();
}

/** One encrypted body per subscription — each has its own keys, so the same payload is
 *  encrypted once per endpoint. */
async function encryptPayloadFor(db, subs, payload) {
  const out = new Map();
  for (const sub of subs) {
    try { out.set(sub.endpoint, await encryptPayload(sub.keys, payload)); }
    catch (e) { console.error('push encrypt failed', e.message); }
  }
  return out;
}

/* ---------- rest timers (in-memory, per device — see the header) ---------- */

export function scheduleRestTimer(db, userId, deviceId, sec, lang) {
  db.restTimers ||= new Map();
  const k = `${userId}:${deviceId || ''}`;
  const t = db.restTimers.get(k);
  if (t) clearTimeout(t);
  db.restTimers.set(k, setTimeout(() => {
    db.restTimers.delete(k);
    sendPush(db, userId, restTimerPush(lang), deviceId);
  }, sec * 1000));
}
export function cancelRestTimer(db, userId, deviceId) {
  if (!db.restTimers) return;
  // no device id: an older client — clear everything the account has pending, as it always did
  for (const [k, t] of db.restTimers) {
    if (deviceId ? k === `${userId}:${deviceId}` : k.startsWith(userId + ':')) { clearTimeout(t); db.restTimers.delete(k); }
  }
}
// A device id is what the browser made up for itself (lib/push.js): one short token per browser
// profile, nothing identifying. Anything else is treated as absent.
export const deviceIdOf = v => (typeof v === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(v) ? v : undefined);

/* ---------- the reminder / nudge tick (from Db.alarm) ---------- */

const hhmmToMin = v => {
  const m = /^(\d{2}):(\d{2})$/.exec(v || '');
  return m ? Number(m[1]) * 60 + Number(m[2]) : NaN;
};
// Minutes since the reminder's time on the user's clock; negative before it, NaN when either
// side does not parse. Same-day only — a 23:55 reminder is not owed at 00:05 the next day.
const minutesLate = (time, now) => hhmmToMin(now.hhmm) - hhmmToMin(time);

/** One tick: the "workout planned today" reminder (once per user per local date, inside a
 *  15-minute catch-up window after their chosen time) and the missed-workout nudge on top of
 *  it. The 60 s alarm is coarser than the Node server's 10 s, well inside that window. */
export async function reminderTick(db) {
  for (const user of db.db.users) {
    if (!db.db.subs.some(s => s.userId === user.id)) continue;
    // One user's state is one user's problem: a shape this tick cannot read is logged and
    // skipped, not allowed to take everyone else's reminders down with it.
    try {
      const S = db.stateOf(user.id);
      if (!S?.reminder?.on) continue;
      const now = userNow(S.reminder.tz || 'UTC');
      if (!now) continue;
      // nudge (opt-in on top of the reminder): owed from 20:00 — or 2 h after the reminder —
      // until 21:30 on the user's clock, once per local date, never while a workout is on.
      if (S.reminder.nudge && user.lastNudge !== now.date &&
          nudgeWindowOpen(S.reminder.time, now.hhmm) && !db.presence.has(user.id)) {
        const rid = nudgeFor(S, now.date);
        if (rid) {
          const routine = (S.routines || []).find(r => r?.id === rid);
          console.log('nudge firing', user.id, rid);
          user.lastNudge = now.date;
          db.saveDb();
          await sendPush(db, user.id, nudgePush(S.lang, toneOf(S.reminder), routine, now.date));
        }
      }
      const late = minutesLate(S.reminder.time, now);
      if (!(late >= 0 && late <= REMINDER_WINDOW_MIN)) continue;
      if (user.lastReminder === now.date) continue;
      if ((S.workouts || []).some(w => w?.d === now.date)) continue;
      if (excusedOn(S, now.date)) continue;   // noted as sick, away, …
      const rid = effectiveRoutineId(S, now.date);
      if (!rid) continue;                    // rest day — nothing planned
      const routine = (S.routines || []).find(r => r?.id === rid);
      console.log('reminder firing', user.id, rid);
      user.lastReminder = now.date;
      db.saveDb();
      await sendPush(db, user.id, dayReminderPush(S.lang, routine));
    } catch (e) {
      console.error('reminder tick', user.id, e);
    }
  }
}

/* ---------- routes ---------- */

export function pushRoutes(db) {
  const json = (status, obj) => new Response(JSON.stringify(obj), {
    status,
    headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']]
  });

  return {
    'GET /api/push/public-key': async function () {
      const { publicKey } = await vapidKeys(db);
      return json(200, { key: publicKey });
    },

    'POST /api/push/subscribe': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await db.readBody(request);
      const sub = body.subscription;
      if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) return json(400, { error: 'invalid subscription' });
      const bad = pushEndpointError(sub.endpoint);
      if (bad) return json(400, { error: bad });
      // Only the two keys the push protocol needs are kept: `sub` is caller-supplied and would
      // otherwise put arbitrary fields into db, which every admin route reads back out.
      const keys = { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) };
      const deviceId = deviceIdOf(body.deviceId);
      // An upsert: the client re-sends its subscription on every boot (lib/push.js) so a row this
      // instance lost — pruned after a dead send — comes back without anyone touching Settings.
      // The same endpoint sent again keeps its original `created`.
      const prev = db.db.subs.find(s => s.endpoint === sub.endpoint);
      // No usable id in the request leaves the id the row already has: the request is a
      // re-send, not a request to forget which device the row is.
      const storedDevice = deviceId || prev?.deviceId;
      db.db.subs = db.db.subs.filter(s => s.endpoint !== sub.endpoint);
      // A browser holds one subscription per device, so this cap is far above real use. Without
      // it a single account could pile up endpoints without limit — every one a target sendPush
      // would then contact.
      const mine = db.db.subs.filter(s => s.userId === user.id);
      if (mine.length >= MAX_SUBS_PER_USER) {
        const drop = new Set(mine.slice(0, mine.length - MAX_SUBS_PER_USER + 1).map(s => s.endpoint));
        db.db.subs = db.db.subs.filter(s => !drop.has(s.endpoint));
      }
      db.db.subs.push({ userId: user.id, endpoint: sub.endpoint, keys, ...(storedDevice ? { deviceId: storedDevice } : {}), created: prev?.created || new Date().toISOString() });
      db.saveDb();
      return json(200, { ok: true });
    },

    // Whether this instance still holds the caller's subscription for `endpoint`. The browser's
    // side (PushManager.getSubscription) says nothing about ours — a row pruned after a dead
    // send leaves the browser subscribed to nowhere — so Settings asks here before it shows "on".
    'GET /api/push/status': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const endpoint = new URL(request.url).searchParams.get('endpoint') || '';
      const row = db.db.subs.find(s => s.userId === user.id && s.endpoint === endpoint);
      return json(200, row ? { subscribed: true, deviceId: row.deviceId || null } : { subscribed: false });
    },

    'POST /api/push/unsubscribe': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await db.readBody(request);
      db.db.subs = db.db.subs.filter(s => !(s.userId === user.id && s.endpoint === body.endpoint));
      db.saveDb();
      return json(200, { ok: true });
    },

    'POST /api/push/test': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      await sendPush(db, user.id, testPush(db.stateOf(user.id)?.lang));
      return json(200, { ok: true });
    },

    'POST /api/push/rest-timer': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await db.readBody(request);
      // Validated before it is clamped: the clamp used to run first, which turned a missing or
      // unusable value into a 1-second push and made the 400 below unreachable.
      const raw = body.seconds;
      const n = typeof raw === 'number' || typeof raw === 'string' ? Number(raw) : NaN;
      if (!(n >= 1)) return json(400, { error: 'seconds required' });
      const sec = Math.min(3600, Math.round(n));
      scheduleRestTimer(db, user.id, deviceIdOf(body.deviceId), sec, db.stateOf(user.id)?.lang);
      return json(200, { ok: true });
    },

    'POST /api/push/rest-timer/cancel': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await db.readBody(request);
      cancelRestTimer(db, user.id, deviceIdOf(body.deviceId));
      return json(200, { ok: true });
    }
  };
}
