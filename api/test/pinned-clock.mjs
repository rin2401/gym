/* Makes `new Date()` and Date.now() start at 2026-07-25 and keep running from there.
 *
 * sampleState() and the coach tests carry workouts dated July 2026, and the review window
 * counts back from "today". On the real clock those fixtures age out of the window (12 weeks)
 * and every review test turns into a `nochange`. The clock still ticks, so the polling loops
 * and timeouts in these tests behave as before; only the starting date is pinned.
 * Import it first in a test file, before anything that reads the date.
 */
const RealDate = Date;
const offset = new RealDate('2026-07-25T12:00:00Z').getTime() - RealDate.now();
globalThis.Date = class extends RealDate {
  constructor(...a) { if (a.length) super(...a); else super(RealDate.now() + offset); }
  static now() { return RealDate.now() + offset; }
};
