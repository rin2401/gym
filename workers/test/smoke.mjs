/* End-to-end smoke test for the Workers port: boots `wrangler dev` locally and walks the
   whole passkey + sync flow against it with a software authenticator — the same P-256 fake
   api/test/server-passkeys.test.js uses, hand-rolled CBOR and all.
 *
 *   health → config → register (options/verify) → me → data GET/PUT → conflict →
 *   login (options/verify) → pair create/redeem → logout
 *
 * Run: npm test (from workers/). Exits non-zero on the first mismatch.
 */
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Against a deployed instance: SMOKE_API=https://… SMOKE_RP_ID=… SMOKE_ORIGIN=… npm test
// (the ceremony checks the clientData origin/rpId against the server's own vars, so all
// three must be the deployed ones). Default: a local `wrangler dev` on a scratch port.
const PORT = 8799;
const API = process.env.SMOKE_API || `http://127.0.0.1:${PORT}`;
const RP_ID = process.env.SMOKE_RP_ID || 'localhost';
const ORIGIN = process.env.SMOKE_ORIGIN || 'http://localhost:8080';

const b64u = b => Buffer.from(b).toString('base64url');
const sha = b => crypto.createHash('sha256').update(b).digest();

/* Just enough CBOR for an attestation object (copied from the api tests). */
const cborHead = (major, n) => n < 24 ? Buffer.from([(major << 5) | n])
  : n < 256 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
const cborText = s => Buffer.concat([cborHead(3, Buffer.byteLength(s)), Buffer.from(s)]);
const cborBytes = b => Buffer.concat([cborHead(2, b.length), b]);

function softPasskey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(jwk.x, 'base64url'),
    Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y, 'base64url')
  ]);
  const raw = crypto.randomBytes(16);
  const id = b64u(raw);
  let counter = 0;
  return {
    id,
    attestation(challenge) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: ORIGIN, crossOrigin: false }));
      const len = Buffer.from([raw.length >> 8, raw.length & 255]);
      const authData = Buffer.concat([sha(RP_ID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), len, raw, cose]);
      const attestationObject = Buffer.concat([
        Buffer.from([0xa3]), cborText('fmt'), cborText('none'), cborText('attStmt'), Buffer.from([0xa0]),
        cborText('authData'), cborBytes(authData)
      ]);
      return {
        id, rawId: id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform',
        response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ['internal', 'hybrid'] }
      };
    },
    assertion(challenge) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }));
      const c = Buffer.alloc(4); c.writeUInt32BE(++counter);
      const authData = Buffer.concat([sha(RP_ID), Buffer.from([0x05]), c]);
      const signature = crypto.sign('sha256', Buffer.concat([authData, sha(clientDataJSON)]), privateKey);
      return {
        id, rawId: id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform',
        response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: null }
      };
    }
  };
}

async function req(method, p, { body, cookie, bearer } = {}) {
  const res = await fetch(API + p, {
    method,
    headers: {
      ...(body != null ? { 'Content-Type': 'application/json' } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...(bearer ? { Authorization: 'Bearer ' + bearer } : {})
    },
    body: body != null ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json (a static asset, an error page) */ }
  return { status: res.status, json, setCookie: res.headers.getSetCookie?.() || [], text };
}

function check(ok, msg, extra) {
  if (!ok) { console.error('FAIL:', msg, extra ?? ''); process.exitCode = 1; throw new Error(msg); }
  console.log('ok  ', msg);
}

async function main() {
  let stop = () => {};
  if (!process.env.SMOKE_API) {
    const wrangler = spawn('npx', [
      'wrangler', 'dev', '--port', String(PORT), '--local',
      // wrangler.jsonc carries the deployed RP_ID/ORIGIN; the local defaults above are what the
      // ceremony here signs with, so they are overridden back for the local server.
      '--var', `RP_ID:${RP_ID}`, '--var', `ORIGIN:${ORIGIN}`
    ], {
      cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
      // A process group of its own, so stopping the test kills npx, wrangler and workerd
      // together — killing only the npx wrapper leaves the rest holding the pipes open.
      detached: true
    });
    let log = '', done = false;
    wrangler.stdout.on('data', d => log += d);
    wrangler.stderr.on('data', d => log += d);
    stop = () => {
      done = true;
      try { process.kill(-wrangler.pid, 'SIGKILL'); } catch { /* already gone */ }
    };
    process.on('exit', stop);
    wrangler.on('exit', () => { if (!done) { console.error('wrangler dev died:\n' + log); process.exit(1); } });
  }

  // Readiness: poll /api/health until the worker answers.
  let up = false;
  for (let i = 0; i < 60 && !up; i++) {
    await new Promise(r => setTimeout(r, 1000));
    try { const r = await req('GET', '/api/health'); up = r.status === 200; } catch { /* not yet */ }
  }
  check(up, 'server is up');

  const health = await req('GET', '/api/health');
  check(health.status === 200 && health.json.ok === true && health.json.writable === true, 'health: ok + writable', health);

  const conf = await req('GET', '/api/config');
  check(conf.status === 200 && conf.json.invite_only === false && conf.json.allow_guest === true, 'config: public flags', conf);

  const key = softPasskey();
  const ro = await req('POST', '/api/register/options', { body: { name: 'Quoc' } });
  check(ro.status === 200 && ro.json.cid && ro.json.options.challenge, 'register/options: challenge out', ro);
  const rv = await req('POST', '/api/register/verify', { body: { cid: ro.json.cid, credential: key.attestation(ro.json.options.challenge) } });
  check(rv.status === 200 && rv.json.user.name === 'Quoc', 'register/verify: profile made', rv);
  const cookie = rv.setCookie.map(c => c.split(';')[0]).join('; ');
  check(/^(gymsid|__Host-gymsid)=/.test(cookie), 'register/verify: session cookie set', rv.setCookie);

  const me = await req('GET', '/api/me', { cookie });
  check(me.status === 200 && me.json.user.name === 'Quoc', 'me: session reads back', me);

  const d0 = await req('GET', '/api/data', { cookie });
  check(d0.status === 200 && d0.json.rev === 0 && d0.json.state == null, 'data GET: empty profile, rev 0', d0);

  const state = { routines: [{ id: 'r1', name: 'Push', _ts: Date.now() }], workouts: [], _ts: Date.now() };
  const p1 = await req('PUT', '/api/data', { cookie, body: { state, baseRev: 0 } });
  check(p1.status === 200 && p1.json.rev === 1 && p1.json.wid, 'data PUT: first write, rev 1', p1);

  const d1 = await req('GET', '/api/data', { cookie });
  check(d1.status === 200 && d1.json.rev === 1 && d1.json.state.routines[0].name === 'Push', 'data GET: the write reads back', d1);

  const conflict = await req('PUT', '/api/data', { cookie, body: { state, baseRev: 0 } });
  check(conflict.status === 409 && conflict.json.rev === 1 && conflict.json.state != null, 'data PUT: stale baseRev answered 409 + document', conflict);

  const rev = await req('GET', '/api/data/rev', { cookie });
  check(rev.status === 200 && rev.json.rev === 1 && rev.json.wid === p1.json.wid, 'data/rev: cheap poll agrees', rev);

  const lo = await req('POST', '/api/login/options', { body: {} });
  check(lo.status === 200 && lo.json.options.challenge, 'login/options: challenge out', lo);
  const lv = await req('POST', '/api/login/verify', { body: { cid: lo.json.cid, credential: key.assertion(lo.json.options.challenge) } });
  check(lv.status === 200 && lv.json.user.name === 'Quoc', 'login/verify: passkey signs in', lv);

  const pc = await req('POST', '/api/pair/create', { cookie });
  check(pc.status === 200 && /^[A-Z2-9]{8}$/.test(pc.json.code), 'pair/create: code minted', pc);
  const pr = await req('POST', '/api/pair/redeem', { body: { code: pc.json.code } });
  check(pr.status === 200 && pr.json.token && pr.json.user.id === lv.json.user.id, 'pair/redeem: bearer token out', pr);
  const mePhone = await req('GET', '/api/me', { bearer: pr.json.token });
  check(mePhone.status === 200 && mePhone.json.user.name === 'Quoc', 'me (bearer): the phone is signed in', mePhone);

  const out = await req('POST', '/api/logout', { cookie });
  check(out.status === 200, 'logout: ok', out);
  const meOut = await req('GET', '/api/me', { cookie: out.setCookie.map(c => c.split(';')[0]).join('; ') });
  check(meOut.status === 401, 'me after logout: cookie cleared', meOut);

  /* ---------- Settings → Passkeys, and the device-link flow (#95) ---------- */

  // A fresh profile for this half, with its own passkey.
  const key2 = softPasskey();
  const ro2 = await req('POST', '/api/register/options', { body: { name: 'Other' } });
  const rv2 = await req('POST', '/api/register/verify', { body: { cid: ro2.json.cid, credential: key2.attestation(ro2.json.options.challenge) } });
  check(rv2.status === 200, 'passkeys: second profile made', rv2);
  const cookie2 = rv2.setCookie.map(c => c.split(';')[0]).join('; ');

  const list0 = await req('GET', '/api/account/passkeys', { cookie: cookie2 });
  check(list0.status === 200 && list0.json.passkeys.length === 1 && list0.json.lastWayIn === true, 'passkeys: list, one, last way in', list0);

  // The step-up proof every account-changing action asks for: a login challenge answered by
  // a passkey of the profile.
  const stepUp = async (key, cookie) => {
    const lo = await req('POST', '/api/login/options', { body: {} });
    return { cid: lo.json.cid, credential: key.assertion(lo.json.options.challenge) };
  };

  // The code the other device redeems (Settings → Account → Add another device).
  const dl = await req('POST', '/api/account/device-link', { cookie: cookie2, body: await stepUp(key2) });
  check(dl.status === 200 && /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(dl.json.code), 'device-link: code minted', dl);

  // Redeeming from the new device: options carry the owner's name and id, then the new passkey
  // is stored, the code burned, and the new device signed in by the passkey it just made.
  const dlo = await req('POST', '/api/device-link/options', { body: { code: dl.json.code } });
  check(dlo.status === 200 && dlo.json.name === 'Other' && dlo.json.options.challenge, 'device-link/options: owner named', dlo);
  const key3 = softPasskey();
  const dlv = await req('POST', '/api/device-link/verify', {
    body: { code: dl.json.code, cid: dlo.json.cid, name: 'Laptop', credential: key3.attestation(dlo.json.options.challenge) }
  });
  check(dlv.status === 200 && dlv.json.user.name === 'Other', 'device-link/verify: new device signed in', dlv);
  const cookie3 = dlv.setCookie.map(c => c.split(';')[0]).join('; ');
  const me3 = await req('GET', '/api/me', { cookie: cookie3 });
  check(me3.status === 200 && me3.json.user.name === 'Other', 'device-link: the new device has a session', me3);

  // The code is one-shot: a second redeem of the same code is refused.
  const dlo2 = await req('POST', '/api/device-link/options', { body: { code: dl.json.code } });
  check(dlo2.status === 400 && dlo2.json.code === 'link-invalid', 'device-link: burned code refused', dlo2);

  const list1 = await req('GET', '/api/account/passkeys', { cookie: cookie2 });
  check(list1.status === 200 && list1.json.passkeys.length === 2 && list1.json.lastWayIn === false, 'passkeys: two now, not last way in', list1);

  // The new passkey signs in on its own.
  const lo3 = await req('POST', '/api/login/options', { body: {} });
  const lv3 = await req('POST', '/api/login/verify', { body: { cid: lo3.json.cid, credential: key3.assertion(lo3.json.options.challenge) } });
  check(lv3.status === 200, 'passkeys: the linked passkey signs in', lv3);

  const ren = await req('POST', '/api/account/passkeys/rename', { cookie: cookie2, body: { id: key3.id, name: 'Work laptop' } });
  check(ren.status === 200 && ren.json.passkeys.find(p => p.id === key3.id).name === 'Work laptop', 'passkeys: renamed', ren);

  // Removing the second one, with the proof, goes; the last way in is then refused.
  const del3 = await req('DELETE', '/api/account/passkeys?id=' + encodeURIComponent(key3.id), { cookie: cookie2, body: await stepUp(key2) });
  check(del3.status === 200 && del3.json.passkeys.length === 1, 'passkeys: second one removed with proof', del3);
  const delLast = await req('DELETE', '/api/account/passkeys?id=' + encodeURIComponent(key2.id), { cookie: cookie2, body: await stepUp(key2) });
  check(delLast.status === 409 && delLast.json.code === 'last-way-in', 'passkeys: last way in refused', delLast);
  const lo4 = await req('POST', '/api/login/options', { body: {} });
  const lv4 = await req('POST', '/api/login/verify', { body: { cid: lo4.json.cid, credential: key3.assertion(lo4.json.options.challenge) } });
  check(lv4.status === 404, 'passkeys: the removed one no longer signs in', lv4);

  // The static frontend: the asset handler serves the built app on the same origin.
  const index = await fetch(API + '/');
  const html = await index.text();
  check(index.status === 200 && /<div id="root">|<script/.test(html), 'static: index.html served at /', { status: index.status });

  console.log('\nall green');
  stop();
}

main().catch(e => { console.error(e); process.exit(process.exitCode || 1); });
