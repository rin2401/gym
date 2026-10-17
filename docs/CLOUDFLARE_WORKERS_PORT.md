# Porting the API to Cloudflare Workers (design sketch)

Target: run the whole openGym stack — frontend and API — on Cloudflare's free tier,
for a personal instance of 2–3 profiles. Not a line-by-line port plan; the shape of
the thing, for review before any code moves.

## Why this shape

The API is already single-instance by design: one `db.json` held in memory, one
`state-<uid>.json` per profile, in-memory rate-limit maps, `setInterval` timers in
the process. That maps 1:1 onto **one Durable Object** — no sharding, no D1 needed.
Media bytes (the only large, blob-shaped data) go to **R2**, which has free egress
and is served from the edge. The frontend is static and rides along as the Worker's
static assets, keeping the single-origin property the passkey/CSRF design requires.

## Resources to create (all free tier)

| Resource | Name (suggestion) | Purpose |
|---|---|---|
| Worker | `opengym` | routes + static assets (frontend `dist/`) |
| Durable Object class `Db` | 1 instance | db.json, state-*, secret, vapid, audit, rate-limit |
| R2 bucket | `opengym-media` | `uploads/<uid>/<sha256>.<ext>` |
| (optional) cron trigger | 1 | coach cadence / GC — or DO alarm instead |

No KV (1k writes/day free is too tight for state), no D1 (DO SQLite covers it),
no Queues.

## wrangler.jsonc (sketch)

```jsonc
{
  "name": "opengym",
  "main": "src/worker.js",
  "compatibility_date": "2025-01-01",
  "compatibility_flags": ["nodejs_compat"],   // web-push, @simplewebauthn/server
  "assets": { "directory": "../frontend/dist" },  // single origin: static + /api/*
  "durable_objects": { "bindings": [{ "name": "DB", "class_name": "Db" }] },
  "r2_buckets": { "bindings": [{ "name": "MEDIA", "bucket_name": "opengym-media" }] },
  "vars": { "RP_ID": "gym.example.com", "ORIGIN": "https://gym.example.com", "MEDIA_UPLOADS": "on" }
  // secrets (wrangler secret put): none needed — secret/vapid are generated into the DO
}
```

`assets` serving the frontend means no separate Pages project and no Worker-route
proxying: the Worker answers `/api/*`, everything else falls through to the static
asset handler. `RP_ID` must equal the domain the site is served from (passkeys bind
to it), same as the docker setup.

## The Db durable object

### Storage layout

The current files become rows in one SQLite-backed DO. Documents stay documents —
no relational rewrite; the sync protocol and admin routes keep reading whole
documents, and porting them is mechanical where storage is untouched.

| Today (DATA_DIR) | In the DO |
|---|---|
| `db.json` (+`.bak`) | `docs` table, key `db` — the `.bak` dance is deleted: DO storage is transactional, a torn write cannot happen |
| `state-<uid>.json` | `docs` table, key `state:<uid>` |
| `secret` (session HMAC key) | `kv` table, key `secret` — generated on first boot, same as today |
| `vapid.json` | `kv` table, key `vapid` |
| `audit.log` (append-only) | `audit` table, one row per event (`id` monotonic, same semantics as `auditSeq`) |
| rate-limit backoff/window Maps | in-memory in the DO instance (it stays warm; the 1-minute sweep becomes an alarm) |
| device links, invites | inside the `db` document, as today |

```sql
CREATE TABLE IF NOT EXISTS docs (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv  (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL, event TEXT NOT NULL, uid TEXT, detail TEXT
);
```

`saveDb()` becomes `UPDATE docs SET value = ? WHERE key = 'db'` inside the same
request that mutated `db` — the fsync/rename machinery in `durable.js` is deleted
rather than ported. `loadDb`'s refuse-to-boot-on-corruption path also goes: DO
SQLite gives us the same guarantee it was earning with fsync.

Sessions stay stateless signed cookies (HMAC over the session id with `secret`),
so there is no session table to port.

### What does NOT get ported as-is

- `durable.js` — deleted (see above).
- `media.js` filesystem half — replaced by R2 (below); the validation half
  (magic numbers, mvhd box walk, limits) ports unchanged.
- `setInterval` timers (`coach/cadence.js`, `coach/warmup.js`, media GC) —
  DO `alarm()`. The cadence/warmup tick becomes one alarm rescheduled per tick.
  Coach is the optional build target anyway; the default target needs only the
  media GC and nudge scheduling.
- `node:http` plumbing in `server.js` — the route table (`'GET /api/data'` keys,
  ~50 routes) ports to a fetch-handler router; `json()`, cookie reading, body
  parsing get small Workers equivalents. Route logic itself is I/O-agnostic.

## Coach (ported — see `workers/src/coach/`)

The AI Coach runs on this deployment, configured through the admin dashboard
exactly as on the Node server (Settings → Coach: provider, base URL, key,
model — nothing in env vars but the `COACH_DISABLED` kill switch and
`ADMIN_UIDS`). What the port consists of:

- `core/` is copied verbatim from `api/coach/core/` — it is Node-free by design
  (the phone imports the same files for BYOK mode), so prompt assembly, payload,
  the invoke→parse→validate→repair pipeline and the plan fingerprint are one
  implementation across server, phone and Worker.
- Only the plain-HTTPS providers exist here (`adapters.js`): no child process can
  be spawned inside a Worker, so the claude/codex runtimes and the fixture CLI
  are not offered. The default provider is `compatible` (OpenAI-compatible
  endpoint) — the whole reason this port exists.
- `store.js` — `coach.json` becomes a `docs` row, per-user records
  (`coach:user:<uid>`) and per-profile credentials too; the credential blob is
  AES-256-GCM via WebCrypto, HKDF-derived from the instance `secret` (node:crypto
  cipher support on workerd is thinner than the Node path needs).
- `jobs.js` — same queue/single-flight/caps/history shapes; a job runs under
  `ctx.waitUntil` so the 202 that enqueued it does not wait for the provider. A
  job that was running when the object was evicted is recovered lazily (the
  status poll and the boot scan mark it failed `restart` — the honest answer
  `recoverOnBoot` gives on the Node server).
- `cadence.js` — the 60 s `setInterval` tick is the DO `alarm()`; the due-date
  logic (weekly slot, every-N-workouts) is copied verbatim. `warmup.js` is not
  ported: it exists to keep a *local* llama.cpp/Ollama prefix cache warm, which
  is not this deployment's shape.
- Push notifications for finished proposals are not ported (no web-push on this
  deployment); the proposal is waiting on the Coach screen either way.

## Media on R2

Same layout as today: `uploads/<uid>/<sha256>.<ext>`, named by content hash,
per-profile directory as the access unit.

- **PUT /api/media/{hash}**: Worker checks auth + limits (ported from `media.js`),
  streams the body to `MEDIA.put()`, verifying the sha256 (hash while streaming;
  a 40 MB video fits the 128 MB Worker memory limit fine at this scale).
- **GET /api/media/{hash}**: after auth, **302 to the R2 object** on a custom
  domain (`media.example.com/<uid>/<hash>.<ext>`). The client's `apiBlob` uses
  `fetch`, which follows redirects transparently — no client change. The sha256
  name is a 256-bit capability; for a 2–3 person instance that is the access
  model (documented tradeoff). If that ever feels too open, swap the 302 for a
  presigned URL — one function changes, nothing else.
- **GC** (`media/sweep`, unreferenced-blob cleanup): ports to a DO alarm walking
  the same `docs`/state references; `.gc.json` marks become a `kv` key per uid.

## Free-tier fit (2–3 profiles)

- Workers 100k req/day + DO ~100k req/day: each sync costs ~2; a household uses
  a few percent.
- R2: 200 MiB default quota/profile → ≤ ~600 MB against 10 GB free.
- Catalogue media (~140 MB) is static assets — served free, cached at the edge.
- **The one paid-tier item**: password login. `password.js` runs scrypt
  N = 2^15 (~50–150 ms CPU) against the Workers Free 10 ms CPU/request limit.
  Passkey-only (the default, `PASSWORD_LOGIN` off) stays free. Turning password
  login on means Workers Paid ($5/mo) — or dropping scrypt cost, which we won't.

## Port order (each step deployable and testable)

1. **Skeleton**: wrangler config, Worker with static assets, `Db` DO with the
   schema above, `GET /api/health` + `GET /api/config` reading real env.
   Frontend build wired in (`npm run build` → `assets`).
2. **Auth**: register/login passkey routes, session cookie, `/api/me`, logout.
   (`@simplewebauthn/server` runs on Workers; `RP_ID`/`ORIGIN` from vars.)
3. **Sync**: `GET/PUT /api/data`, `/api/data/rev`, `sync-stamps.js` ported —
   the heart of the app; everything else is support.
4. **Media**: R2 put/get + redirect, limits, GC alarm.
5. **Admin, audit, push**: admin dashboard routes on the DO, `audit` table,
   web-push via `nodejs_compat` (VAPID keys from `kv`).
6. **Coach (optional target)**: cadence/warmup as DO alarms, same route logic.

Steps 1–3 give a usable passkey-syncing instance; 4–5 complete parity with the
docker deployment's default target.
