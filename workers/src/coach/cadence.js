/* Scheduled reviews (Epic E) — the port of api/coach/cadence.js.
 *
 * The Node server ticks a 60-second setInterval; a Worker has no long-lived timer, so the
 * tick is the Durable Object's alarm (set every minute from Db.alarm). The due-date logic —
 * isDue, the wall-clock-to-instant resolution of the weekly slot, the "reviewed means the
 * model read those workouts" marker — is copied verbatim, because it is the part that
 * decides whether somebody's evening gets a provider call spent on it.
 *
 * Skips are silent and logged, never pushed (FR-36/E4), exactly as there.
 */
import * as jobs from './jobs.js';

const TICK_MS = 60000;
export { TICK_MS };

/** Weekly cadence fires within the minute; everyWorkouts fires as soon as the count is met.
 *  `reviewedAt` is when the server last finished a review for this person: the client stamps
 *  lastReview only once someone acts on a proposal, and a review nobody has opened yet — or
 *  one that found nothing to change — still read those workouts. */
export function isDue(coach, S, now, reviewedAt = 0, tz = null) {
  const cadence = coach.cadence;
  if (!cadence || cadence === 'off') return false;
  const lastAt = Math.max(coach.lastReview?.at || 0, reviewedAt);

  // Nothing new to read is the most common reason not to run, and it applies to both modes.
  const workouts = S.workouts || [];
  // A workout's `end` is on the same clock as the review's timestamp; its `d` is the phone's
  // local day, which can run ahead of the server's UTC day, so the date only stands in for a
  // workout that has no end.
  const since = workouts.filter(w => !lastAt || (w.end ? w.end > lastAt : w.d > new Date(lastAt).toISOString().slice(0, 10)));
  if (!since.length) return false;

  if (cadence.everyWorkouts) {
    return since.length >= Math.max(1, Math.min(20, cadence.everyWorkouts));
  }
  if (cadence.weekly) {
    if (!now) return false;
    // Due once the week's slot has passed and this week's review has not run — not on the one
    // minute it falls. The tick is every 60 s and unaligned, so the exact-minute test lost the
    // whole week to a restart, a redeploy or a busy event loop across that minute; the same
    // reason the workout reminder stopped asking for its exact minute. `lastAt` is the marker
    // that says whether it already ran: the server's own finished-review timestamps (the
    // `reviewedAt` the caller computes from the job history) and the client's lastReview.
    const at = weeklySlotAt(now, cadence.weekly.day ?? 0, cadence.weekly.time || '18:00', tz);
    return at != null && lastAt < at;
  }
  return false;
}

/* When this week's slot fell, as an epoch timestamp — the clock `lastAt` is on. (Verbatim
   from cadence.js; see there for the two-pass offset resolution argument.) */
function weeklySlotAt(now, wantDay, wantTime, tz) {
  const d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(now.date || '');
  const nowMin = hhmmToMin(now.hhmm), wantMin = hhmmToMin(wantTime);
  if (!d || !Number.isFinite(nowMin) || !Number.isFinite(wantMin)) return null;
  const midnight = Date.UTC(+d[1], +d[2] - 1, +d[3]);
  let back = (now.weekday - wantDay + 7) % 7;
  if (back === 0 && nowMin < wantMin) back = 7;
  const wall = midnight - back * 86400000 + wantMin * 60000;
  const here = midnight + nowMin * 60000;
  return wall - offsetAt(tz, wall - offsetAt(tz, Date.now(), here), here);
}
/* The zone's offset from UTC at one instant, in ms: what a wall clock reading there is ahead
   of the instant it names. Without a usable zone — no tz, or a string Intl refuses — it falls
   back to the offset where the caller is right now, which is all this ever had to go on. */
function offsetAt(tz, ms, hereWall) {
  try {
    const p = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).formatToParts(new Date(ms));
    const g = t => Number(p.find(x => x.type === t).value);
    return Date.UTC(g('year'), g('month') - 1, g('day'), g('hour'), g('minute'), g('second')) - ms;
  } catch {
    return hereWall - Date.now();
  }
}
const hhmmToMin = v => {
  const m = /^(\d{1,2}):(\d{2})$/.exec(v || '');
  return m ? Number(m[1]) * 60 + Number(m[2]) : NaN;
};

/** The user's own wall clock (date, hh:mm, weekday) in a zone — port of server.js userNow. */
export function userNow(tz) {
  try {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, hour12: false,
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).formatToParts(new Date());
    const g = t => parts.find(p => p.type === t)?.value;
    const date = `${g('year')}-${g('month')}-${g('day')}`;
    // Weekday is derived from the zone's own date, not the object's — a Sunday-evening review
    // has to be Sunday where the user is, which is what the reminder already assumes for time.
    return { date, hhmm: `${g('hour')}:${g('minute')}`, weekday: new Date(date + 'T12:00:00Z').getUTCDay() };
  } catch { return null; } // unknown/invalid tz string — skip this user rather than guess
}

/**
 * One tick, from Db.alarm: every profile with consent and a due cadence gets a scheduled
 * review enqueued. `users` is the DO's own db.users.
 */
export async function tick(C, users) {
  if (!C.isEnabled() || !(await C.isConnected())) return;
  for (const user of users) {
    try {
      const S = C.readState(user.id);
      const coach = S?.coach;
      if (!coach?.consent?.agreedAt) continue;         // consent revoked ⇒ cadence stops
      // A job still running, or a proposal nobody has answered, is not a reason for another:
      // a second review would only replace the first unread. status() also retires an expired
      // proposal, which a phone that stays closed never polls for.
      const st = jobs.status(C, user.id);
      if (st.job || st.pending) continue;
      // Reviewed means the model read those workouts and answered — with a proposal, with
      // "nothing to change", or with an answer that failed validation and was paid for all the
      // same. A call that never reached it (timeout, consent, switched off) is retried.
      const reviewedAt = Math.max(0, ...C.readUser(user.id).history
        .filter(h => h.kind === 'review' && (h.outcome === 'ready' || h.outcome === 'nochange'
          || (h.outcome === 'failed' && h.errorClass === 'unusable')))
        .map(h => h.at || 0));
      const tz = coach.cadence?.weekly ? (S.reminder?.tz || 'UTC') : null;
      const now = tz ? userNow(tz) : null;
      if (!isDue(coach, S, now, reviewedAt, tz)) continue;
      await jobs.enqueue(C, user.id, { kind: 'review', trigger: 'scheduled' });
      console.log('coach: scheduled review queued for', user.id);
    } catch (e) {
      // Caps, an in-flight job, a provider that just went down: all ordinary, all silent.
      if (!(e instanceof jobs.CoachError)) console.error('coach cadence', user.id, e);
    }
  }
}
