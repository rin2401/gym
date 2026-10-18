/* Photos, GIFs and videos of a person's own exercises on the Worker — the port of
 * api/media.js to an object store: a Workers KV namespace today (this account has no
 * payment info on file, so R2's enable gate is out; KV's free tier — 1 GB, egress free —
 * covers a household), an R2 bucket unchanged tomorrow if one is ever bound (see
 * kvObjectStore for the adapter that makes the two interchangeable).
 *
 * Same promises (never decodes media beyond magic numbers and the mvhd box; never deletes
 * because something is missing; the directory — here the prefix — is the access check).
 * What differs:
 *
 *   - the bytes live under uploads/<uid>/<sha256>.<ext> in the object store, not DATA_DIR/uploads;
 *     a put is atomic, so the temp-file dance and cleanTmp() have no counterpart;
 *   - an upload is read into memory (capped at the kind's limit, 40 MB worst case — well
 *     under the 128 MB a Worker may hold) and hashed with WebCrypto, instead of streamed
 *     through a hash to a file;
 *   - the .gc.json marks are a docs row ('media:gc:<uid>'), the same transactional store
 *     everything else here uses;
 *   - the per-profile cache of {hash → ext, size} is built from one R2 list per profile
 *     and kept current by every write/delete, so a state push never lists the bucket.
 *
 * The whole module is inert while no MEDIA binding exists (see db.js): the routes answer
 * 404 and /api/config says nothing, which is how the client knows the feature is off —
 * the same contract a Node server with MEDIA_UPLOADS=0 has. The one KV-specific clamp:
 * a value is capped at 25 MB, so db.js caps the video limit at 20 MB.
 */
const MB = 1024 * 1024;          // every *_MB setting means MiB; the client uses the same unit
const HOUR = 3600000;
const DAY = 24 * HOUR;
const HEAD_BYTES = 64;            // enough for every magic number below, the WebM DocType included
const MOOV_MAX = 8 * MB;          // a real moov for a 60 s clip is well under 1 MB
const MAX_BOXES = 10000;
export const MAX_INFLIGHT = 2;    // concurrent uploads per profile

export const HASH_RE = /^[0-9a-f]{64}$/;

/* The seven types that are ever stored. `category` is what the client may not lie about: a
   JPEG declared as a GIF is still a still image and is stored as the JPEG it is, but a video
   declared as an image would slip past the image cap, so that mismatch is refused. */
export const MEDIA_TYPES = {
  'image/jpeg': { kind: 'image', category: 'still', ext: 'jpg' },
  'image/png': { kind: 'image', category: 'still', ext: 'png' },
  'image/webp': { kind: 'image', category: 'still', ext: 'webp' },
  'image/gif': { kind: 'gif', category: 'still', ext: 'gif' },
  'video/mp4': { kind: 'video', category: 'video', ext: 'mp4' },
  'video/quicktime': { kind: 'video', category: 'video', ext: 'mov' },
  'video/webm': { kind: 'video', category: 'video', ext: 'webm' }
};
const EXT_MIME = Object.fromEntries(Object.entries(MEDIA_TYPES).map(([mime, t]) => [t.ext, mime]));
const FILE_RE = /^([0-9a-f]{64})\.(jpg|png|webp|gif|mp4|mov|webm)$/;

/* ---------------------------------------------------------------- limits */

const OFF = /^(0|false|no|off)$/i;
/** The instance's media settings, read from the environment (docs/SELF_HOSTING.md). Every MB
 *  value is MiB and may be fractional. A value that does not parse falls back to its default
 *  rather than to 0: a typo must not turn the quota off or refuse every upload. */
export function mediaLimits(env = {}) {
  const num = (key, def, min) => {
    const raw = env[key];
    if (raw == null || String(raw).trim() === '') return def;
    const n = Number(raw);
    return Number.isFinite(n) && n >= min ? n : def;
  };
  return {
    enabled: !OFF.test(String(env.MEDIA_UPLOADS || '').trim()),
    quotaMB: num('MEDIA_QUOTA_MB', 200, 0),              // 0 = no cap
    imageMB: num('MEDIA_IMAGE_MAX_MB', 2, 0.001),
    gifMB: num('MEDIA_GIF_MAX_MB', 8, 0.001),
    videoMB: num('MEDIA_VIDEO_MAX_MB', 40, 0.001),
    videoSec: num('MEDIA_VIDEO_MAX_SEC', 60, 1),
    gcGraceDays: num('MEDIA_GC_GRACE_DAYS', 14, 0),
    uploadsPerHour: Math.floor(num('MEDIA_UPLOADS_PER_HOUR', 600, 1))
  };
}
/** The block GET /api/config hands out. Public: the caps are not a secret, and the editor needs
 *  them before the first upload to refuse a file the server would refuse anyway. `workouts: true`:
 *  this server keeps the files a logged workout's `media` names, so a signed-in client may offer
 *  attaching them. */
export const mediaConfig = l => ({ imageMB: l.imageMB, gifMB: l.gifMB, videoMB: l.videoMB, videoSec: l.videoSec, quotaMB: l.quotaMB, workouts: true });

/* ---------------------------------------------------------------- errors */

const MESSAGES = {
  'bad-request': 'bad request',
  'media-type': 'that file type is not accepted',
  'media-too-large': 'that file is too large',
  'media-quota': 'your space for photos and videos is full',
  'media-invalid': 'that video could not be read',
  'media-too-long': 'that video is too long',
  'media-missing': 'no such file',
  'hash-mismatch': 'the file does not match its name',
  busy: 'too many uploads at once, try again in a moment',
  locked: 'too many uploads, try again later',
  timeout: 'the upload stalled'
};
/** A refusal the client caused or can act on, answered as {error, code, ...extra} with its
 *  status, and not logged: a refused file is not a server error. */
export class MediaError extends Error {
  constructor(status, code, extra = {}) {
    super(MESSAGES[code] || code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/* ---------------------------------------------------------------- sniffing (verbatim from api/media.js) */

const MP4_BRANDS = new Set([
  'isom', 'iso2', 'iso3', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'M4VP',
  'dash', 'mmp4', 'MSNV', '3gp4', '3gp5', '3gp6', '3g2a'
]);

// An EBML variable-length integer at b[i]. IDs keep their length marker, sizes drop it.
function vint(b, i, keepMarker) {
  if (i >= b.length || b[i] === 0) return null;
  const first = b[i];
  let len = 1;
  while (!(first & (0x80 >> (len - 1)))) len++;
  if (i + len > b.length) return null;
  let v = keepMarker ? first : first & (0xff >> len);
  for (let k = 1; k < len; k++) v = v * 256 + b[i + k];
  return { value: v, len };
}
// The DocType of an EBML header ('webm', 'matroska'), read off the header's children.
function ebmlDocType(b) {
  const hs = vint(b, 4, false);
  if (!hs) return null;
  let i = 4 + hs.len;
  const end = Math.min(b.length, i + hs.value);
  while (i < end) {
    const id = vint(b, i, true);
    const sz = id && vint(b, i + id.len, false);
    if (!sz) return null;
    const body = i + id.len + sz.len;
    if (id.value === 0x4282) {
      if (body + sz.value > b.length) return null;
      return Buffer.from(b.subarray(body, body + sz.value)).toString('latin1').replace(/\0+$/, '');
    }
    i = body + sz.value;
  }
  return null;
}

/** What a file is, from its first bytes alone — never from its name or a declared type.
 *  Returns { mime, kind, category, ext } or null (verbatim from api/media.js). */
export function sniffMedia(head) {
  const b = Buffer.isBuffer(head) ? head : Buffer.from(head || []);
  const as = mime => ({ mime, ...MEDIA_TYPES[mime] });
  const at = (off, ...bytes) => bytes.every((x, i) => b[off + i] === x);
  const ascii = (off, len) => b.length >= off + len ? b.toString('latin1', off, off + len) : '';
  if (at(0, 0xff, 0xd8, 0xff)) return as('image/jpeg');
  if (at(0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return as('image/png');
  if (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a') return as('image/gif');
  if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return as('image/webp');
  if (ascii(4, 4) === 'ftyp') {
    const brand = ascii(8, 4);
    if (brand === 'qt  ') return as('video/quicktime');
    if (MP4_BRANDS.has(brand)) return as('video/mp4');
    return null;       // HEIC/AVIF stills, M4A audio and every brand nobody vouched for
  }
  if (at(0, 0x1a, 0x45, 0xdf, 0xa3)) return ebmlDocType(b) === 'webm' ? as('video/webm') : null;
  return null;
}

/* ---------------------------------------------------------------- MP4 / MOV (on a Buffer — the whole upload is in memory anyway) */

// The box whose header starts at `pos`, which must end by `end`. size 1 = a 64-bit size follows,
// size 0 = the box runs to `end`. Anything that would reach outside its parent is a broken file.
function boxAt(b, pos, end) {
  if (end - pos < 8) return null;
  const h = b.subarray(pos, Math.min(pos + 16, end));
  let size = h.readUInt32BE(0);
  let headerLen = 8;
  if (size === 1) {
    if (h.length < 16) return null;
    size = u64(h, 8);
    if (size === Number.MAX_SAFE_INTEGER) return null;
    headerLen = 16;
  } else if (size === 0) size = end - pos;
  if (size < headerLen || pos + size > end) return null;
  return { type: h.toString('latin1', 4, 8), body: pos + headerLen, bodyLen: size - headerLen, end: pos + size };
}
// A 64-bit field as a Number, clamped: nothing in a real file comes near 2^53, and all ones (the
// "unknown" marker) has to stay recognisable after the conversion.
const u64 = (buf, off) => { const v = buf.readBigUInt64BE(off); return v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v); };
// A duration field that says "unknown": zero (fragmented files) or all ones.
const unknownDur = (d, version) => d === 0 || d === (version === 1 ? Number.MAX_SAFE_INTEGER : 0xffffffff);

/** The brand and length of an MP4/MOV, read from box headers — the same walk api/media.js
 *  does with positioned reads, on the Buffer this deployment already holds. Returns
 *  { brand, durationSec } — durationSec null when the file does not say — or null for
 *  anything that is not a well-formed file. */
export function mp4Info(b, size) {
  try {
    let pos = 0, count = 0, brand = null, moov = null;
    while (pos < size) {
      if (++count > MAX_BOXES) return null;
      const bx = boxAt(b, pos, size);
      if (!bx) return null;
      if (count === 1) {
        if (bx.type !== 'ftyp' || bx.bodyLen < 4) return null;
        brand = b.toString('latin1', bx.body, bx.body + 4);
      }
      if (bx.type === 'moov') { moov = bx; break; }
      pos = bx.end;
    }
    if (!moov || moov.bodyLen + 8 > MOOV_MAX) return null;
    let timescale = 0, dur = null, fragDur = null, sawMvhd = false;
    pos = moov.body;
    while (pos < moov.end) {
      if (++count > MAX_BOXES) return null;
      const bx = boxAt(b, pos, moov.end);
      if (!bx) return null;
      if (bx.type === 'mvhd' && !sawMvhd) {
        sawMvhd = true;
        const v = b.subarray(bx.body, Math.min(bx.body + 32, bx.end));
        if (v.length < 20) return null;
        if (v[0] === 1) {
          if (v.length < 32) return null;
          timescale = v.readUInt32BE(20);
          dur = u64(v, 24);
          if (unknownDur(dur, 1)) dur = null;
        } else {
          timescale = v.readUInt32BE(12);
          dur = v.readUInt32BE(16);
          if (unknownDur(dur, 0)) dur = null;
        }
      } else if (bx.type === 'mvex') {
        // A fragmented file (Safari's MediaRecorder, some editors) leaves mvhd at 0 and states
        // the whole length here, in mehd, in the same timescale.
        let p = bx.body;
        while (p < bx.end) {
          if (++count > MAX_BOXES) return null;
          const c = boxAt(b, p, bx.end);
          if (!c) return null;
          if (c.type === 'mehd') {
            const v = b.subarray(c.body, Math.min(c.body + 12, c.end));
            if (v.length >= 8) {
              const wide = v[0] === 1 && v.length >= 12;
              const d = wide ? u64(v, 4) : v.readUInt32BE(4);
              if (!unknownDur(d, wide ? 1 : 0)) fragDur = d;
            }
          }
          p = c.end;
        }
      }
      pos = bx.end;
    }
    if (!sawMvhd || !timescale) return null;
    const ticks = dur ?? fragDur;
    return { brand, durationSec: ticks == null ? null : Math.round((ticks / timescale) * 1000) / 1000 };
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------- references (verbatim) */

/** Every blob a state refers to: customEx[].media.hash and .poster.hash, and the same two of
 *  every entry of workouts[].media. Deliberately loose — each field counts on its own as long
 *  as it is a well-formed hash. This set decides what is KEPT, so erring towards more is the
 *  safe direction. `active` is not walked: PUT /api/data drops it before the state is stored. */
export function referencedHashes(state) {
  const out = new Set();
  if (!state || typeof state !== 'object') return out;
  const isObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
  const add = r => { if (r && typeof r === 'object' && typeof r.hash === 'string' && HASH_RE.test(r.hash)) out.add(r.hash); };
  const ref = m => { add(m); add(m.poster); };
  for (const c of Array.isArray(state.customEx) ? state.customEx : []) {
    if (isObj(c) && isObj(c.media)) ref(c.media);
  }
  for (const w of Array.isArray(state.workouts) ? state.workouts : []) {
    if (!isObj(w) || !Array.isArray(w.media)) continue;
    for (const m of w.media) if (isObj(m)) ref(m);
  }
  return out;
}

/* ---------------------------------------------------------------- the store (R2 / KV) */

/** A KV namespace dressed as the object store createMediaStore expects — the same three
 *  operations (list-by-prefix, put, get) plus delete, which is all the store uses, so an R2
 *  binding and a KV namespace are interchangeable. What the adapter papers over:
 *  KV's list returns keys + metadata instead of objects with sizes (the size rides in the
 *  value's metadata at put time), get returns an ArrayBuffer instead of a stream, and
 *  delete takes one key at a time. */
export function kvObjectStore(kv) {
  return {
    async list({ prefix, cursor }) {
      const page = await kv.list({ prefix, cursor });
      return {
        objects: page.keys.map(k => ({ name: k.name, size: k.metadata?.size ?? 0 })),
        truncated: !page.list_complete,
        cursor: page.list_complete ? undefined : page.cursor
      };
    },
    async put(key, data) {
      // The size rides in the metadata so the store's entry cache can be built from list
      // alone — the same place an R2 list gets it from.
      await kv.put(key, data, { metadata: { size: data.byteLength } });
    },
    async get(key) {
      const buf = await kv.get(key, 'arrayBuffer');
      return buf ? { body: buf } : null;
    },
    async delete(keys) {
      for (const k of Array.isArray(keys) ? keys : [keys]) await kv.delete(k);
    }
  };
}

const round1 = n => Math.round(n * 10) / 10;
const b64u = buf => Buffer.from(buf).toString('base64url');

/**
 * The per-instance media store. `bucket` is the MEDIA binding dressed as an object store
 * (an R2 binding as-is, or a KV namespace through kvObjectStore); `sql` the DO's SQLite
 * (the gc marks are a docs row); `readState(uid)` the profile's stored state, or null.
 */
export function createMediaStore({ bucket, sql, limits, env, readState = () => null, now = Date.now, log = console } = {}) {
  const L = { ...mediaLimits(env), ...(limits || {}) };
  const quotaBytes = L.quotaMB > 0 ? Math.round(L.quotaMB * MB) : 0;
  const capMB = kind => (kind === 'video' ? L.videoMB : kind === 'gif' ? L.gifMB : L.imageMB);
  const capOf = kind => Math.round(capMB(kind) * MB);
  const maxCap = Math.max(capOf('image'), capOf('gif'), capOf('video'));
  const users = new Map();          // safe uid -> { bytes, count, reserved, inflight, hashes }

  // The same sanitising as db.js stateKey. An id that sanitises to nothing would name the
  // prefix of everybody's files, and removeUser() would then delete them all.
  function safe(uid) {
    const s = String(uid ?? '').replace(/[^a-zA-Z0-9_-]/g, '');
    if (!s) throw new Error('media: a profile id is required');
    return s;
  }
  const prefix = id => `uploads/${id}/`;
  const objKey = (id, hash, ext) => `${prefix(id)}${hash}.${ext}`;

  // Built once per profile from one R2 list, then kept current by every write and delete.
  async function entry(uid) {
    const id = safe(uid);
    let e = users.get(id);
    if (e) return e;
    e = { id, bytes: 0, count: 0, reserved: 0, inflight: 0, hashes: new Map() };
    let cursor;
    do {
      const page = await bucket.list({ prefix: prefix(id), cursor });
      for (const obj of page.objects) {
        const m = FILE_RE.exec(obj.name.slice(prefix(id).length));
        if (!m || e.hashes.has(m[1])) continue;
        e.hashes.set(m[1], { ext: m[2], size: obj.size });
        e.bytes += obj.size;
        e.count++;
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    users.set(id, e);
    return e;
  }
  const usageOf = e => ({ bytes: e.bytes, count: e.count, quotaBytes });

  /* gc marks: when each stored hash was last seen leaving the state — a docs row, the same
     transactional store everything else here uses. Unreadable = no marks: the grace starts
     over, which can only ever keep a file longer. */
  const gcKey = e => 'media:gc:' + e.id;
  function readMarks(e) {
    try {
      const row = sql.exec(`SELECT value FROM docs WHERE key = ?`, gcKey(e)).toArray()[0];
      const raw = row ? JSON.parse(row.value) : {};
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
      const out = {};
      for (const [h, t] of Object.entries(raw)) if (HASH_RE.test(h) && Number.isFinite(t)) out[h] = t;
      return out;
    } catch { return {}; }
  }
  function writeMarks(e, marks) {
    sql.exec(`INSERT OR REPLACE INTO docs (key, value) VALUES (?, ?)`, gcKey(e), JSON.stringify(marks));
  }
  // Brings the marks in line with `refs`: a referenced hash loses its mark, an unreferenced one
  // without a mark gets `t`, marks for files that are gone are dropped.
  function reconcile(e, refs, marks, t) {
    let changed = false;
    for (const h of e.hashes.keys()) {
      if (refs.has(h)) { if (h in marks) { delete marks[h]; changed = true; } }
      else if (!(h in marks)) { marks[h] = t; changed = true; }
    }
    for (const h of Object.keys(marks)) if (!e.hashes.has(h)) { delete marks[h]; changed = true; }
    return changed;
  }
  function stateOf(uid) {
    let S = null;
    try { S = readState(uid); } catch { S = null; }
    return S && typeof S === 'object' && !Array.isArray(S) ? S : null;
  }

  async function noteState(uid, state) {
    const id = safe(uid);
    if (!users.has(id)) return false;      // a profile that never uploaded — the common case
    const e = await entry(uid);
    if (!e.hashes.size) return false;
    const marks = readMarks(e);
    const changed = reconcile(e, referencedHashes(state), marks, now());
    if (changed) writeMarks(e, marks);
    return changed;
  }

  async function sweep(uid, { graceMs = L.gcGraceDays * DAY } = {}) {
    const e = await entry(uid);
    const res = { removed: 0, freedBytes: 0, skipped: false };
    if (!e.hashes.size) return res;
    const S = stateOf(uid);
    if (!S) { res.skipped = true; return res; }   // never infer anything from a missing state
    const refs = referencedHashes(S);
    const marks = readMarks(e);
    const t = now();
    let changed = reconcile(e, refs, marks, t);
    for (const [h, f] of [...e.hashes]) {
      if (refs.has(h)) continue;
      if (graceMs > 0 && !(t - marks[h] >= graceMs)) continue;
      try { await bucket.delete(objKey(e.id, h, f.ext)); }
      catch (err) { log.error('media: could not delete', e.id, h, err.message); continue; }
      e.hashes.delete(h);
      e.bytes -= f.size;
      e.count--;
      delete marks[h];
      changed = true;
      res.removed++;
      res.freedBytes += f.size;
    }
    if (changed) writeMarks(e, marks);
    return res;
  }

  async function sweepAll({ uids = [], graceMs } = {}) {
    const out = { swept: 0, removed: 0, freedBytes: 0, skipped: 0 };
    for (const uid of uids) {
      try {
        const r = await sweep(uid, graceMs === undefined ? {} : { graceMs });
        if (r.skipped) out.skipped++; else out.swept++;
        out.removed += r.removed;
        out.freedBytes += r.freedBytes;
      } catch (err) { log.error('media: sweep failed for', uid, err.message); }
    }
    return out;
  }

  function markIfUnreferenced(uid, e, hash) {
    const S = stateOf(uid);
    if (S && referencedHashes(S).has(hash)) return;
    const marks = readMarks(e);
    marks[hash] = now();
    writeMarks(e, marks);
  }
  // A device just vouched for a file the server already has. If it was on its way out, the
  // grace starts over: the state push that references it is usually a second behind.
  function touch(e, hash) {
    const marks = readMarks(e);
    if (!(hash in marks)) return;
    marks[hash] = now();
    writeMarks(e, marks);
  }

  /** Reads the request body into memory, refusing past `max` bytes. Resolves with the whole
   *  buffer — an upload is capped at 40 MB, well under what a Worker may hold, and R2 needs
   *  the bytes (or a stream we have already validated) as one put. */
  async function readAll(request, max) {
    const reader = request.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) throw new MediaError(413, 'media-too-large', { maxMB: max / MB });
      chunks.push(value);
    }
    const out = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.byteLength; }
    return out;
  }

  async function receive(uid, hash, request) {
    if (!HASH_RE.test(String(hash))) throw new MediaError(400, 'bad-request');
    const e = await entry(uid);
    if (e.inflight >= MAX_INFLIGHT) throw new MediaError(429, 'busy', { retryAfter: 5 });
    e.inflight++;
    let reserved = 0;
    try {
      const declared = MEDIA_TYPES[String(request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase()];
      if (!declared) throw new MediaError(415, 'media-type');
      const cap = capOf(declared.kind);
      const lenRaw = request.headers.get('content-length');
      const len = lenRaw != null && lenRaw !== '' && Number.isSafeInteger(+lenRaw) && +lenRaw >= 0 ? +lenRaw : null;
      if (len != null && len > cap) throw new MediaError(413, 'media-too-large', { maxMB: capMB(declared.kind) });

      // A file this profile already has is taken as it is. (The Node server can catch a damaged
      // file by stat-ing it; R2 objects are atomic, so what the cache knows is what is there.)
      const have = e.hashes.get(hash);
      if (have && (len == null || len === have.size)) { touch(e, hash); return { status: 200, body: { ok: true, hash, mime: EXT_MIME[have.ext], size: have.size, existed: true } }; }

      // Reserved before a byte is read, so two uploads at once cannot both fit into the space
      // that is only left for one.
      const need = len ?? cap;
      if (quotaBytes && e.bytes + e.reserved + need > quotaBytes) {
        // Space the person already let go of may still be sitting out its grace period; under
        // pressure it gets an hour instead of two weeks.
        try { await sweep(uid, { graceMs: HOUR }); } catch (err) { log.error('media: quota sweep failed for', e.id, err.message); }
        if (e.bytes + e.reserved + need > quotaBytes) {
          throw new MediaError(413, 'media-quota', { usedMB: round1(e.bytes / MB), quotaMB: L.quotaMB });
        }
      }
      e.reserved += need;
      reserved = need;

      const buf = await readAll(request, cap);
      const sha = Buffer.from(await crypto.subtle.digest('SHA-256', buf)).toString('hex');
      if (sha !== hash) throw new MediaError(400, 'hash-mismatch');
      const sn = sniffMedia(buf.subarray(0, HEAD_BYTES));
      if (!sn || sn.category !== declared.category) throw new MediaError(415, 'media-type');
      if (buf.length > capOf(sn.kind)) throw new MediaError(413, 'media-too-large', { maxMB: capMB(sn.kind) });
      if (sn.ext === 'mp4' || sn.ext === 'mov') {
        const info = mp4Info(buf, buf.length);
        if (!info) throw new MediaError(415, 'media-invalid');
        // One second of slack: the client measures with the platform's player, which rounds.
        if (info.durationSec != null && info.durationSec > L.videoSec + 1) throw new MediaError(413, 'media-too-long', { maxSec: L.videoSec });
      }

      // The same bytes from another device may have landed while these were read. The put and
      // the cache update below are on the DO's single thread, so this check cannot be overtaken.
      const now2 = e.hashes.get(hash);
      if (now2 && (len == null || len === now2.size)) {
        touch(e, hash);
        return { status: 200, body: { ok: true, hash, mime: EXT_MIME[now2.ext], size: now2.size, existed: true } };
      }
      const damaged = e.hashes.get(hash);
      if (damaged && damaged.ext !== sn.ext) await bucket.delete(objKey(e.id, hash, damaged.ext));
      await bucket.put(objKey(e.id, hash, sn.ext), buf, { httpMetadata: { contentType: sn.mime } });   // httpMetadata is R2's; the KV adapter ignores it
      e.hashes.set(hash, { ext: sn.ext, size: buf.length });
      e.bytes += buf.length;
      e.count++;
      // Unreferenced until the state push that names it arrives; the mark is what lets the
      // grace protect it until then, and what lets it go if that push never comes.
      try { markIfUnreferenced(uid, e, hash); } catch (err) { log.error('media: could not mark', e.id, hash, err.message); }
      return { status: 201, body: { ok: true, hash, mime: sn.mime, size: buf.length, existed: false } };
    } catch (err) {
      // A refusal mid-body: the reader is already cancelled by the throw unwinding, and the
      // DO's fetch drains what is left of the request (see db.js).
      throw err;
    } finally {
      e.reserved -= reserved;
      e.inflight--;
    }
  }

  return {
    limits: L,
    usage: async uid => usageOf(await entry(uid)),
    has: async (uid, hash) => (await entry(uid)).hashes.has(hash),
    /** { key, ext, mime, size } of a stored object, or null. */
    async file(uid, hash) {
      const e = await entry(uid);
      const f = e.hashes.get(hash);
      if (!f) return null;
      return { key: objKey(e.id, hash, f.ext), ext: f.ext, mime: EXT_MIME[f.ext], size: f.size };
    },
    /** The bytes of a stored object (whatever the bucket is), or null. */
    async get(f) {
      const obj = await bucket.get(f.key);
      return obj ? obj.body : null;
    },
    receive,
    async missing(uid, hashes) {
      const e = await entry(uid);
      // A file that is not whole counts as missing: the device that has it sends it again.
      return { missing: [...new Set(hashes)].filter(h => !e.hashes.has(h)), usage: usageOf(e) };
    },
    noteState,
    sweep,
    sweepAll,
    /** Admin delete: the profile's whole prefix. */
    async removeUser(uid) {
      const id = safe(uid);
      users.delete(id);
      sql.exec(`DELETE FROM docs WHERE key = ?`, 'media:gc:' + id);
      let cursor;
      do {
        const page = await bucket.list({ prefix: prefix(id), cursor });
        const keys = page.objects.map(o => o.name);
        if (keys.length) await bucket.delete(keys);
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
    }
  };
}

/* ---------------------------------------------------------------- routes */

/** The media HTTP surface. `hash` is stashed on the request by db.js's dispatch (the
 *  route-table keys are exact pathnames; /api/media/<hash> is the one dynamic path).
 *  Every route is absent while no MEDIA binding exists — a 404 is what a server from
 *  before the feature answers, and the client already treats that as "this server does
 *  not store them". */
export function mediaRoutes(db) {
  const json = (status, obj) => new Response(JSON.stringify(obj), {
    status,
    headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']]
  });
  const M = () => db.media;

  return {
    'PUT /api/media/{hash}': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      // The hourly budget: the same shape the Node server's mediaThrottle has, per profile.
      const wait = db.mediaWindow.take('up:' + user.id);
      if (wait) return json(429, { error: 'too many uploads, try again later', code: 'locked', retryAfter: wait }, [['Retry-After', String(wait)]]);
      try {
        const r = await M().receive(user.id, request.mediaHash, request);
        return json(r.status, r.body);
      } catch (e) {
        if (e instanceof MediaError) return json(e.status, { error: e.message, code: e.code, ...e.extra });
        throw e;
      }
    },

    'GET /api/media/{hash}': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const f = await M().file(user.id, request.mediaHash);
      if (!f) return json(404, { error: 'no such file', code: 'media-missing' });
      const body = await M().get(f);
      if (body == null) return json(404, { error: 'no such file', code: 'media-missing' });
      // Hash-named and immutable: the one place a long private cache is honest.
      return new Response(body, {
        status: 200,
        headers: [
          ['Content-Type', f.mime],
          ['Content-Length', String(f.size)],
          ['Cache-Control', 'private, max-age=31536000, immutable'],
          ['ETag', '"' + request.mediaHash + '"']
        ]
      });
    },

    /* Which of the hashes the caller's state names the server does not have yet — the sync
       protocol's other half. The client uploads what this answers, then re-asks. */
    'POST /api/media/missing': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const body = await db.readBody(request);
      const hashes = Array.isArray(body.hashes) ? body.hashes.filter(h => HASH_RE.test(h)) : [];
      return json(200, await M().missing(user.id, hashes));
    },

    /* A manual GC pass for this profile: everything their state does not name, grace off. */
    'POST /api/media/sweep': async function (request) {
      const user = db.readSession(request);
      if (!user) return json(401, { error: 'not signed in' });
      const r = await M().sweep(user.id, { graceMs: 0 });
      return json(200, { removed: r.removed, freedBytes: r.freedBytes, usage: await M().usage(user.id) });
    }
  };
}
