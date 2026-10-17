/* "Compare with others here" — the port of api/coach/cohort.js.
 *
 * Same two gates (the admin's instance switch, each person's own opt-in), same coarse
 * medians, same floors. Only the reads differ: the state documents live in the DO's docs
 * table instead of ./data/state-<uid>.json, and the config comes from the Coach store.
 * The cache rides on the Coach instance (C.cohortCache) — the DO is the single thread.
 */
import { libraryHas, libraryName } from './core/library.js';

export const MIN_PEOPLE = 3;
export const MAX_EXERCISES = 12;
const WEEKS_STRENGTH = 12;
const WEEKS_FREQUENCY = 8;
const CACHE_MS = 5 * 60000;
const LB_TO_KG = 0.45359237;
const REP_CAP = 12;   // mirrors frontend/src/lib/onerm.js: past twelve reps the estimate stops meaning much

// Mirror of frontend/src/lib/workout-model.js isWarmupRow: an explicit phase wins over the
// legacy boolean.
const isWarmup = s => {
  const ph = typeof s?.phase === 'string' ? s.phase.trim().toLowerCase() : '';
  if (ph) return ph === 'warmup' || ph === 'warm-up' || ph === 'warm_up';
  return s?.warmup === true;
};
const epley = (w, r) => w * (1 + Math.min(r, REP_CAP) / 30);
const round1 = n => Math.round(n * 10) / 10;
const median = arr => {
  const a = arr.filter(n => Number.isFinite(n)).sort((x, y) => x - y);
  return a.length ? a[Math.floor(a.length / 2)] : null;
};
const isoDaysAgo = days => { const d = new Date(); d.setDate(d.getDate() - days); return d.toISOString().slice(0, 10); };

/** One participant, reduced to what the cohort reads: kg throughout (see cohort.js). */
function participant(S) {
  const since = isoDaysAgo(WEEKS_STRENGTH * 7);
  const sinceFreq = isoDaysAgo(WEEKS_FREQUENCY * 7);
  const toKg = S.unit === 'lb' ? LB_TO_KG : 1;
  const workouts = (S.workouts || []).filter(w => w && w.d && w.d >= since);
  if (!workouts.length) return null;
  const best = {};
  workouts.forEach(w => (w.entries || []).forEach(en => {
    if (!libraryHas(en?.id)) return;
    (en.sets || []).forEach(s => {
      if (!s.done || isWarmup(s) || !(s.w > 0) || !(s.r > 0)) return;
      const est = epley(s.w * toKg, s.r);
      if (est > (best[en.id] || 0)) best[en.id] = est;
    });
  }));
  const recent = workouts.filter(w => w.d >= sinceFreq).length;
  return { sessionsPerWeek: round1(recent / WEEKS_FREQUENCY), best };
}

export const invalidate = C => { C.cohortCache = null; };

function rows(C) {
  if (C.cohortCache && Date.now() - C.cohortCache.at < CACHE_MS) return C.cohortCache.rows;
  const out = new Map();
  for (const uid of C.listUserIds()) {
    if (!isSharing(C, uid)) continue;
    const S = C.readState(uid);
    if (!S) continue;
    const p = participant(S);
    if (p) out.set(uid, p);
  }
  C.cohortCache = { at: Date.now(), rows: out };
  return out;
}

/** Everything the sheet shows, in the requester's unit. */
export function computeCohort(C, uid) {
  if (!isSharing(C, uid)) return { ok: false, enabled: true, sharing: false };
  const all = rows(C);
  const people = all.size;
  if (people < MIN_PEOPLE) return { ok: false, enabled: true, sharing: true, people, minPeople: MIN_PEOPLE };

  const me = all.get(uid) || null;
  const S = C.readState(uid);
  const unit = S?.unit === 'lb' ? 'lb' : 'kg';
  const out = v => (v == null ? null : round1(unit === 'lb' ? v / LB_TO_KG : v));

  const byEx = new Map();
  for (const p of all.values()) {
    for (const [id, est] of Object.entries(p.best)) {
      if (!byEx.has(id)) byEx.set(id, []);
      byEx.get(id).push(est);
    }
  }
  const exercises = [...byEx.entries()]
    .filter(([, list]) => list.length >= MIN_PEOPLE)
    .map(([id, list]) => ({ id, name: libraryName(id), people: list.length, medianKg: median(list), youKg: me?.best[id] ?? null, list }))
    .sort((a, b) => b.people - a.people || a.name.localeCompare(b.name))
    .slice(0, MAX_EXERCISES);

  // Where the requester stands: for each listed exercise they trained, the share of the
  // *other* participants whose best is at or below theirs, averaged.
  const ranks = exercises.filter(x => x.youKg != null).map(x => {
    const others = x.list.length - 1;
    if (others <= 0) return null;
    const below = x.list.filter(v => v <= x.youKg).length - 1;
    return below / others;
  }).filter(v => v != null);
  const rankPct = ranks.length ? Math.round(ranks.reduce((a, b) => a + b, 0) / ranks.length * 100) : null;

  return {
    ok: true, enabled: true, sharing: true, people, minPeople: MIN_PEOPLE, unit,
    sessionsPerWeek: { median: median([...all.values()].map(p => p.sessionsPerWeek)), you: me?.sessionsPerWeek ?? 0 },
    exercises: exercises.map(x => ({ id: x.id, name: x.name, people: x.people, median: out(x.medianKg), you: out(x.youKg) })),
    rankPct
  };
}

/** The compact form a prompt gets — kg regardless of the requester's unit, or null. */
export function cohortForPayload(C, uid) {
  try {
    if (!C.load().community || !isSharing(C, uid)) return null;
    const all = rows(C);
    if (all.size < MIN_PEOPLE) return null;
    const me = all.get(uid) || null;
    const byEx = new Map();
    for (const p of all.values()) for (const [id, est] of Object.entries(p.best)) {
      if (!byEx.has(id)) byEx.set(id, []);
      byEx.get(id).push(est);
    }
    const exercises = [...byEx.entries()]
      .filter(([, list]) => list.length >= MIN_PEOPLE)
      .map(([id, list]) => ({ id, name: libraryName(id), median: round1(median(list)), you: me?.best[id] != null ? round1(me.best[id]) : null }))
      .sort((a, b) => (b.you != null) - (a.you != null) || a.name.localeCompare(b.name))
      .slice(0, MAX_EXERCISES);
    return {
      unit: 'kg', people: all.size,
      sessionsPerWeek: { median: median([...all.values()].map(p => p.sessionsPerWeek)), you: me?.sessionsPerWeek ?? 0 },
      exercises
    };
  } catch { return null; }
}

/* The share flag lives in the server's own per-profile record (see jobs.js), not in the
   synced state — a stale device syncing an older copy of S must not be able to flip it. */
export const isSharing = (C, uid) => !!C.readUser(uid).share;
export function setShare(C, uid, share) {
  C.patchUser(uid, { share: !!share });
  invalidate(C);
  return !!share;
}
