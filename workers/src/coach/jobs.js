/* Running Coach jobs on the Worker — the port of api/coach/jobs.js.
 *
 * Same contract, same shapes: the server owns proposals (never the synced state blob, which
 * any device can overwrite), jobs cannot pile up, cannot run forever, and cannot lie about
 * what happened. What differs:
 *
 *   - the per-user record is a docs row ('coach:user:<uid>') instead of ./data/coach/<uid>.json;
 *   - there is no child process and no privilege drop — only the plain-HTTPS adapters exist
 *     here (see adapters.js), so the whole jobDir/spawn/unprivileged half of the Node module
 *     has no counterpart;
 *   - "the process died" is "the DO was evicted": a job that was running when the object
 *     went away is recovered lazily (recoverStale on boot and from the status poll), the
 *     same honest answer the Node server gives at recoverOnBoot, without a boot hook to
 *     hang it on;
 *   - a job runs under ctx.waitUntil so the object outlives the 202 that enqueued it.
 */
import * as payloadLib from './core/payload.js';
import { runPipeline } from './core/pipeline.js';
import { extractJSON } from './core/parse.js';
import { hashPlan } from './core/plan-hash.js';
import { handleFor } from './handle.js';
import { adapterFor } from './adapters.js';
import { cohortForPayload, invalidate as invalidateCohort } from './cohort.js';

// Re-exported for the same reason the Node module does: the prompt assembly and the plan
// fingerprint are core, and callers should not have to reach into core/ to get them.
export { hashPlan };
export { buildPrompt } from './core/prompt.js';

// Five minutes by default, as on the Node server. COACH_JOB_TIMEOUT_MS overrides, never
// below one minute.
export const TIMEOUT_MS = Math.max(60000, +(globalThis.process?.env?.COACH_JOB_TIMEOUT_MS) || 5 * 60000);
const MAX_CONCURRENT = 2;          // these are minutes-scale jobs on one object
const PENDING_DAYS = 14;           // FR-33
const HISTORY_MAX = 20;
// How long a "running" job may outlive its own timeout before the status poll declares it
// dead with the object (see recoverStale) — the timeout itself, plus a margin for a repair
// round and the DO's own scheduling.
const STALE_GRACE_MS = 10 * 60000;

/* ---------- per-user store ---------- */

export const readUser = (C, uid) => C.readUser(uid);
export const writeUser = (C, uid, rec) => C.writeUser(uid, rec);
const patchUser = (C, uid, patch) => C.patchUser(uid, patch);

/** Consent revoked, profile deleted, "reset everything" — no server-side residue (FR-51).
 *  Today's job count stays: it is the spending record the daily cap reads, not the
 *  profile's data (see jobs.js for the full argument). */
export function clearUser(C, uid) {
  const { daily } = C.readUser(uid);
  C.sql.exec(`DELETE FROM docs WHERE key = ?`, 'coach:user:' + String(uid).replace(/[^a-zA-Z0-9_-]/g, ''));
  if (daily?.date === C.todayISO()) C.writeUser(uid, { daily, current: null, pending: null, history: [] });
  const queued = C.queue.findIndex(j => j.uid === uid);
  if (queued >= 0) { C.queue.splice(queued, 1); C.inflight.delete(uid); }
  C.aborts.get(uid)?.abort();
  C.forgetSeq.set(uid, (C.forgetSeq.get(uid) || 0) + 1);
  invalidateCohort(C);
}

export const isSharing = (C, uid) => !!C.readUser(uid).share;
export const readState = (C, uid) => C.readState(uid);

/* ---------- caps ---------- */

const capState = (C, uid) => C.capState(uid);

/* ---------- status ---------- */

/** What the client polls. Expiry is enforced lazily here rather than on a timer. */
export function status(C, uid) {
  const rec = C.readUser(uid);
  // A job that was running when the object was evicted is not coming back (see the header).
  // The poll that notices is the one that says so, so no spinner outlives the object.
  if (rec.current && Date.now() - (rec.current.startedAt || 0) > TIMEOUT_MS + STALE_GRACE_MS) {
    retireStale(C, uid, rec);
    return { job: null, pending: null, cap: capState(C, uid) };
  }
  if (rec.pending && rec.pending.expiresAt && rec.pending.expiresAt < Date.now()) {
    archive(C, uid, rec, 'expired');
    // Same shape as every other answer: the poll that happens to be the one which expires a
    // proposal must not be the one where the client's cap readout goes undefined.
    return { job: null, pending: null, cap: capState(C, uid) };
  }
  return {
    job: rec.current ? { id: rec.current.id, kind: rec.current.kind, state: rec.current.state, startedAt: rec.current.startedAt } : null,
    pending: rec.pending || null,
    cap: capState(C, uid),
    // How the most recent job ended, so the chat can say "nothing to change" or "that failed"
    // in the Coach's own bubble rather than leaving a job that silently stopped appearing.
    last: lastOutcome(rec)
  };
}
function lastOutcome(rec) {
  const h = (rec.history || []).at(-1);
  return h ? { id: h.id, kind: h.kind, outcome: h.outcome, errorClass: h.errorClass || null, at: h.at, ...(h.reading ? { reading: h.reading } : {}) } : null;
}
function archive(C, uid, rec, outcome) {
  const history = [...(rec.history || []), {
    id: rec.pending?.id, kind: rec.pending?.kind, outcome, at: Date.now()
  }].slice(-HISTORY_MAX);
  patchUser(C, uid, { pending: null, history });
}
function retireStale(C, uid, rec) {
  const history = [...(rec.history || []), {
    id: rec.current.id, kind: rec.current.kind, outcome: 'failed', errorClass: 'restart', at: Date.now()
  }].slice(-HISTORY_MAX);
  C.writeUser(uid, { ...rec, current: null, history });
}

/** The boot-time half of the lazy recovery: every record that still claims a running job
 *  gets the honest answer, the same as recoverOnBoot on the Node server. */
export function recoverStale(C) {
  let n = 0;
  for (const uid of C.listCoachUserIds()) {
    const rec = C.readUser(uid);
    if (!rec.current) continue;
    retireStale(C, uid, rec);
    n++;
  }
  if (n) console.log(`coach: cleared ${n} job(s) interrupted by a restart`);
  return n;
}

/* ---------- the queue ---------- */

export class CoachError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** Clamp a free-text note/refine message to the admin's configured maxMessageLen (issue #267). */
export function clampMessage(C, text) {
  if (!text) return null;
  const max = C.load().maxMessageLen || 1000;
  return String(text).slice(0, max);
}

/**
 * Enqueue a job. Throws CoachError with a code the routes layer maps to an HTTP status:
 * `off`, `busy`, `cap`, `consent`, `shared`. Async here where the Node server's is sync —
 * the credential is decrypted with WebCrypto.
 */
export async function enqueue(C, uid, opts) {
  if (!C.isEnabled() || !(await C.isConnected())) throw new CoachError('off', 'the Coach is not set up on this instance');
  if (C.inflight.has(uid)) throw new CoachError('busy', 'the Coach is already thinking about your training');

  const S = C.readState(uid);
  // Consent is enforced here, server-side, not by the screen that collects it: a UI-only gate
  // is not a gate (FR-08/13).
  if (!S?.coach?.consent?.agreedAt) throw new CoachError('consent', 'the Coach needs your go-ahead first');

  // Whose account pays (see store.js credentialFor for the shared-account posture).
  const cred = await C.credentialFor(uid);
  if (!cred.ok) {
    if (cred.reason === 'shared-account') throw new CoachError('shared', cred.message);
    throw new CoachError('off', 'this profile has no provider account connected');
  }
  // Spending is what binds: a personal credential belongs to the first profile that runs a
  // job on it from here on; an API key binds to nobody and is shared.
  await C.bindInstanceCredential(uid);

  const caps = C.load().caps || {};
  const { used, limit } = capState(C, uid);
  if (limit > 0 && used >= limit) throw new CoachError('cap', 'daily limit reached');
  if (caps.instanceDaily > 0 && C.instanceUsedToday() >= caps.instanceDaily) throw new CoachError('cap', 'this instance has reached its daily limit');

  // Counted at enqueue, not at completion: the cap exists to bound what one profile can spend
  // of the owner's provider account, and queueing twenty jobs spends it whether or not the
  // twentieth ever finishes.
  C.bumpDaily(uid);
  C.bumpInstanceDaily();

  const job = {
    id: Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString('hex'),
    uid,
    forgetSeq: C.forgetSeq.get(uid) || 0,
    kind: opts.kind,                                  // 'create' | 'review' | 'debrief'
    trigger: opts.trigger || 'manual',                // 'manual' | 'scheduled'
    workoutId: opts.workoutId ? String(opts.workoutId).slice(0, 40) : null,
    intake: opts.intake || null,
    note: clampMessage(C, opts.note),
    refine: clampMessage(C, opts.refine),
    lang: payloadLib.langTag(opts.lang),              // the language the app was showing (#303)
    state: 'queued',
    startedAt: Date.now()
  };
  C.inflight.add(uid);
  patchUser(C, uid, { current: { id: job.id, kind: job.kind, state: 'queued', startedAt: job.startedAt } });
  C.queue.push(job);
  pump(C);
  return { id: job.id };
}

function pump(C) {
  while (C.running < MAX_CONCURRENT && C.queue.length) {
    const job = C.queue.shift();
    C.running++;
    // waitUntil keeps the object alive for the job's lifetime; the 202 that enqueued it is
    // long gone by the time a provider answers.
    C._waitUntil(
      execute(C, job)
        .catch(e => { console.error('coach job crashed', job.id, e); finish(C, job, { outcome: 'failed', errorClass: 'internal' }); })
        .finally(() => { C.running--; C.inflight.delete(job.uid); pump(C); })
    );
  }
}

/* Why an answer was rejected, for the admin card (see jobs.js for the FR-12/42 argument). */
export function whyUnusable(errors) {
  if (!Array.isArray(errors) || !errors.length) return null;
  return errors.slice(0, 3).map(e => String(e).replace(/"[^"]*"/g, '"…"')).join('; ').slice(0, 300);
}

function finish(C, job, result) {
  C.logJob({
    at: new Date().toISOString(), uid: job.uid, kind: job.kind, trigger: job.trigger,
    outcome: result.outcome, errorClass: result.errorClass || null,
    ms: Date.now() - job.startedAt, detail: result.detail || null
  });
  // Forgotten while it ran: the record is gone and stays gone, and nobody is notified. The
  // job still ran and still spent, which is why the instance log above keeps its line.
  if ((C.forgetSeq.get(job.uid) || 0) !== job.forgetSeq) return;
  const rec = C.readUser(job.uid);
  const history = [...(rec.history || []), {
    id: job.id, kind: job.kind, trigger: job.trigger, outcome: result.outcome,
    errorClass: result.errorClass || null, at: Date.now(),
    // "Nothing to change" is an answer with a reason attached, and throwing the reason away
    // leaves the user with a job that finished and nothing to show for it.
    ...(result.reading ? { reading: String(result.reading).slice(0, 1200) } : {})
  }].slice(-HISTORY_MAX);
  C.writeUser(job.uid, {
    ...rec,
    current: null,
    pending: result.pending !== undefined ? result.pending : rec.pending,
    history
  });
}

/* ---------- execution ---------- */

async function execute(C, job) {
  patchUser(C, job.uid, { current: { id: job.id, kind: job.kind, state: 'running', startedAt: job.startedAt } });

  const S = C.readState(job.uid);
  if (!S) return finish(C, job, { outcome: 'failed', errorClass: 'nostate' });
  // Checked again here, not only at enqueue: a job can wait behind another, and consent
  // withdrawn or the Coach switched off in the meantime means no payload leaves for it.
  if (!S.coach?.consent?.agreedAt) return finish(C, job, { outcome: 'failed', errorClass: 'consent' });
  if (!C.isEnabled()) return finish(C, job, { outcome: 'failed', errorClass: 'off' });

  const cfg = C.load();
  const adapter = adapterFor(cfg.provider);
  if (!adapter) return finish(C, job, { outcome: 'failed', errorClass: 'off' });

  if (job.kind === 'debrief' && !payloadLib.findWorkout(S, job.workoutId)) {
    return finish(C, job, { outcome: 'failed', errorClass: 'noworkout' });
  }

  const pendingCreate = job.refine ? C.readUser(job.uid).pending : null;
  const payload = payloadLib.build(S, {
    handle: handleFor(C, job.uid),
    kind: job.kind,
    intake: job.intake,
    note: job.note,
    refine: job.refine,
    previous: pendingCreate?.bundle || null,
    workoutId: job.workoutId,
    // A scheduled review has no app behind it: a profile that never picked a language then
    // gets the instance's DEFAULT_LANG, like its screens do.
    lang: job.lang || (S.langAuto === true ? payloadLib.langTag(C.env.DEFAULT_LANG) : null),
    // The room's medians ride along on a review or a debrief when the admin allows it and
    // this person opted in; null otherwise, and the payload then carries no `cohort` at all.
    cohort: (job.kind === 'review' || job.kind === 'debrief') ? cohortForPayload(C, job.uid) : null
  });
  // The payload is paid for with the instance's key, and it is built from state the client
  // wrote. The builder bounds each field; a payload that is still bigger than any real
  // training history makes is refused here, before a provider is called, rather than sent
  // and billed.
  const size = JSON.stringify(payload).length;
  if (size > payloadLib.MAX_PAYLOAD_CHARS) {
    return finish(C, job, { outcome: 'failed', errorClass: 'toolarge', detail: `payload of ${Math.round(size / 1000)}k characters` });
  }

  const env = C.jobEnv(await C.credentialFor(job.uid));
  const ctl = new AbortController();
  C.aborts.set(job.uid, ctl);
  try {
    const attempt = await runPipeline({
      adapter, cfg, kind: job.kind, payload, model: C.modelFor(cfg), timeoutMs: TIMEOUT_MS,
      // The HTTP adapters take the fetch and the abort signal they are given. Workers'
      // own fetch has no undici headers timeout to work around, so the global one is it.
      invokeOpts: { env, fetch: fetch, signal: ctl.signal, maxTokens: cfg.maxOutputTokens }
    });
    if (!attempt.ok) {
      // Cancelled by a forget, not failed by the provider: the log must not blame the job budget.
      const errorClass = ctl.signal.aborted ? 'forgotten' : attempt.errorClass;
      return finish(C, job, { outcome: 'failed', errorClass, detail: attempt.detail || whyUnusable(attempt.errors) });
    }
    if (attempt.nochange) {
      return finish(C, job, { outcome: 'nochange', pending: null, detail: null, reading: attempt.reading });
    }
    const pending = {
      id: job.id,
      kind: job.kind,
      createdAt: Date.now(),
      expiresAt: Date.now() + PENDING_DAYS * 86400000,
      planHash: hashPlan(payloadLib.canonicalPlan(S)),
      iteration: job.refine ? (pendingCreate?.iteration || 1) + 1 : 1,
      // A debrief names the session it read, so the card can show it after the fact.
      ...(job.kind === 'debrief' ? { workout: payloadLib.workoutMeta(S, job.workoutId) } : {}),
      ...attempt.result
    };
    return finish(C, job, { outcome: 'ready', pending });
  } finally {
    C.aborts.delete(job.uid);
  }
}

/* ---------- decisions ---------- */

/** The client has applied (or discarded) the pending proposal. Record it and clear. */
export function resolvePending(C, uid, { accepted = [], rejected = [], dismissed = false } = {}) {
  const rec = C.readUser(uid);
  if (!rec.pending) return { ok: true };
  const history = [...(rec.history || []), {
    id: rec.pending.id, kind: rec.pending.kind,
    outcome: dismissed ? 'dismissed' : 'applied',
    accepted: accepted.length, rejected: rejected.length, at: Date.now()
  }].slice(-HISTORY_MAX);
  C.writeUser(uid, { ...rec, pending: null, history });
  return { ok: true };
}

/* ---------- admin test ---------- */

/** A2's "Test the Coach": the real adapter, a trivial round-trip, no user data anywhere near it. */
export async function testRun(C) {
  const cfg = C.load();
  const adapter = adapterFor(cfg.provider);
  if (!adapter) return { ok: false, error: 'no provider configured' };
  // No user asked for this, so no profile's account is being spent: the bound profile's
  // credential in instance mode — the one the round-trip is meant to prove.
  const env = C.jobEnv(await C.credentialFor(C.boundUidFor(cfg)));
  const check = await adapter.check(cfg, env);
  if (!check.ok) return { ok: false, error: check.error || 'the provider could not be reached' };
  const r = await adapter.invoke({
    cfg, env, model: C.modelFor(cfg), timeoutMs: 90000,
    prompt: 'Reply with exactly this JSON object and nothing else: {"coach_contract":1,"ok":true}'
  });
  if (r.timedOut) return { ok: false, version: check.version, error: 'the provider did not answer in time' };
  if (r.code !== 0) {
    const err = (r.stderr || r.text || '').trim();
    return { ok: false, version: check.version, error: err.slice(0, 300) || 'the provider answered with an error' };
  }
  const parsed = extractJSON(r.text);
  if (parsed.error || !parsed.value?.ok) {
    return { ok: false, version: check.version, error: 'the provider answered, but not in the expected shape' };
  }
  return { ok: true, version: check.version };
}
