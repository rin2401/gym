/* The admin dashboard on the Worker — the port of the admin half of api/server.js.
 *
 * Same routes, same shapes (the Admin view cannot tell them apart): the users list with
 * presence, the per-user drill-down, disable/delete, invites, and the audit log read out
 * of the `audit` table instead of the JSONL file. What differs:
 *
 *   - presence is the DO's own ephemeral Map (same TTL/grace rules as server.js);
 *   - the audit rows come from SQLite, newest first by id, with the same retention the
 *     DO's own compactAudit() enforces on write;
 *   - password fields never exist (no password routes on this deployment), and a user
 *     delete also drops their Coach record and media folder (R2) when those exist.
 */
import crypto from 'node:crypto';
import { dropDeviceLinks } from './device-link.js';

const PRESENCE_TTL = 70000;               // ~3.5× the 20s client heartbeat
const PRESENCE_HIDDEN_GRACE = 45000;       // see server.js for the two-heartbeat argument

const presenceListed = (p, now) =>
  now - p.updatedAt < PRESENCE_TTL && (p.hiddenAt === undefined || now - p.hiddenAt < PRESENCE_HIDDEN_GRACE);

function livePresence(presence, uid) {
  const p = presence.get(uid);
  if (!p) return null;
  if (!presenceListed(p, Date.now())) { presence.delete(uid); return null; }
  const { hiddenAt: _away, ...live } = p;   // the mark is bookkeeping; the dashboard gets the row it always did
  return live;
}

const lastSyncOf = (u, S) => Math.max(S?._ts || 0, u?.lastPull || 0) || null;
const records = v => (Array.isArray(v) ? v.filter(x => !!x && typeof x === 'object' && !Array.isArray(x)) : []);

export function adminRoutes(db) {
  const json = (status, obj) => new Response(JSON.stringify(obj), {
    status,
    headers: [['Content-Type', 'application/json'], ['Cache-Control', 'no-store']]
  });
  const requireAdmin = request => {
    const user = db.readSession(request);
    if (!user) return { answer: json(401, { error: 'not signed in' }) };
    if (!db.isAdmin(user)) return { answer: json(403, { error: 'forbidden' }) };
    return { user };
  };
  const audit = (request, ev, f = {}) => db.audit(request, ev, f);

  return {
    /* One row per user, cheap enough for a personal instance (reads each state doc once). */
    'GET /api/admin/users': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const users = db.db.users.map(u => {
        const state = db.stateOf(u.id) || {};
        const workouts = records(state.workouts);
        const last = workouts[workouts.length - 1];
        return {
          id: u.id, name: u.name, created: u.created || null,
          disabled: !!u.disabled, admin: db.isAdmin(u), invitedBy: u.invitedBy || null,
          workouts: workouts.length,
          lastWorkout: last ? last.d : null,
          lastSync: lastSyncOf(u, state),
          hasPush: db.db.subs.some(s => s.userId === u.id),
          live: livePresence(db.presence, u.id)
        };
      });
      return json(200, { users, invite_only: db.INVITE_ONLY, now: Date.now() });
    },

    /* Drill-down: full workout history + body-weight log for one user. */
    'GET /api/admin/user': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const id = new URL(request.url).searchParams.get('id');
      const u = db.db.users.find(x => x.id === id);
      if (!u) return json(404, { error: 'no such user' });
      const state = db.stateOf(u.id) || {};
      return json(200, {
        user: {
          id: u.id, name: u.name, created: u.created || null, disabled: !!u.disabled,
          admin: db.isAdmin(u), invitedBy: u.invitedBy || null
        },
        unit: state.unit || 'kg',
        lastSync: lastSyncOf(u, state),
        routines: records(state.routines).map(r => ({ id: r.id, name: r.name, emoji: r.emoji, count: records(r.ex).length })),
        bodyweight: records(state.bodyweight),
        // records() already copied, so this reverse is ours: newest first for display. A workout's
        // photos and videos are the owner's own: the admin view gets no refs to them.
        workouts: records(state.workouts).reverse().map(({ media, ...w }) => w)
      });
    },

    'POST /api/admin/user/disable': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await db.readBody(request);
      const u = db.db.users.find(x => x.id === body.id);
      if (!u) return json(404, { error: 'no such user' });
      if (db.isAdmin(u)) return json(400, { error: 'cannot disable an admin' });
      u.disabled = !!body.disabled;
      if (u.disabled) db.presence.delete(u.id);   // drop them off "training now" at once
      // A device link made before the lock would otherwise still be waiting when it is lifted.
      if (u.disabled) dropDeviceLinks(db.db, u.id);
      db.saveDb();
      audit(request, u.disabled ? 'admin.user.disable' : 'admin.user.enable', { user: a.user, target: u });
      return json(200, { ok: true, id: u.id, disabled: u.disabled });
    },

    /* Disable locks an account out; this removes it. The one destructive action in the app, so
       the client asks twice and this end refuses the two cases that cannot be undone from the UI
       afterwards: an admin deleting themselves, and the last admin standing (issue #107). The
       invite code that let them in stays burned — it was used, and freeing it would quietly
       widen an invite-only instance. `GET /api/admin/user` is the export. */
    'POST /api/admin/user/delete': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await db.readBody(request);
      const u = db.db.users.find(x => x.id === body.id);
      if (!u) return json(404, { error: 'no such user' });
      if (u.id === a.user.id) return json(400, { error: 'you cannot delete your own account' });
      if (db.isAdmin(u) && db.db.users.filter(x => db.isAdmin(x)).length <= 1) return json(400, { error: 'cannot delete the last admin' });
      const name = u.name;
      db.db.users = db.db.users.filter(x => x.id !== u.id);
      db.db.creds = (db.db.creds || []).filter(c => c.userId !== u.id);
      db.db.subs = (db.db.subs || []).filter(x => x.userId !== u.id);
      dropDeviceLinks(db.db, u.id);
      db.presence.delete(u.id);
      // The training history, the Coach record and any Coach credential of theirs.
      db.sql.exec(`DELETE FROM docs WHERE key = ?`, db.stateKey(u.id));
      db.sql.exec(`DELETE FROM docs WHERE key = ?`, 'coach:user:' + String(u.id).replace(/[^a-zA-Z0-9_-]/g, ''));
      db.sql.exec(`DELETE FROM docs WHERE key = ?`, 'coach:auth:' + String(u.id).replace(/[^a-zA-Z0-9_-]/g, ''));
      // Their photos and videos — the one place a profile's prefix under uploads/ is removed.
      if (db.media) { try { await db.media.removeUser(u.id); } catch (e) { console.error('media: could not remove uploads of', u.id, e.message); } }
      db.saveDb();
      // Logged with the name, because the id is about to mean nothing to anyone reading this back.
      audit(request, 'admin.user.delete', { user: a.user, msg: name });
      return json(200, { ok: true, id: u.id });
    },

    'GET /api/admin/invites': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      // resolve usedBy uid → name for display
      const invites = db.db.invites.map(i => ({
        ...i, usedByName: i.usedBy ? (db.db.users.find(u => u.id === i.usedBy) || {}).name || null : null
      }));
      return json(200, { invites, invite_only: db.INVITE_ONLY });
    },

    'POST /api/admin/invites/new': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await db.readBody(request);
      let code;
      // 16 hex chars = 64 bits (see server.js for why the code itself has to be the thing
      // that isn't worth guessing). Codes already in db.json keep working — validation is an
      // exact string compare, never a length or format check.
      do { code = crypto.randomBytes(8).toString('hex').toUpperCase(); } while (db.db.invites.some(i => i.code === code));
      const invite = { code, note: String(body.note || '').slice(0, 60), createdBy: a.user.id, created: new Date().toISOString() };
      db.db.invites.push(invite);
      db.saveDb();
      audit(request, 'admin.invite.create', { user: a.user, msg: code });
      return json(200, { invite });
    },

    'POST /api/admin/invites/revoke': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const body = await db.readBody(request);
      const inv = db.db.invites.find(i => i.code === String(body.code || '').toUpperCase());
      if (!inv) return json(404, { error: 'no such code' });
      if (inv.usedBy) return json(400, { error: 'already used, cannot revoke' });
      db.db.invites = db.db.invites.filter(i => i.code !== inv.code);
      db.saveDb();
      audit(request, 'admin.invite.revoke', { user: a.user, msg: inv.code });
      return json(200, { ok: true });
    },

    /* ---------- activity log ----------
       Newest first, paged by id. Not by offset: the log grows at the front of this view, so an
       offset cursor would repeat a row whenever an event lands between two pages; and not by
       timestamp, because two events can share a millisecond. The retention the DO enforces on
       write (compactAudit) is applied on read too, so nothing past it is ever served. */
    'GET /api/admin/audit': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      const q = new URL(request.url).searchParams;
      const limit = Math.max(1, Math.min(200, +q.get('limit') || 100));
      const before = +q.get('before') || Number.MAX_SAFE_INTEGER;
      const cat = q.get('cat') || '';
      const daysCut = db.AUDIT_DAYS ? Date.now() - db.AUDIT_DAYS * 86400000 : 0;
      let rows = db.sql.exec(
        `SELECT id, ts, ev, ok, uid, name, tgt, tname, msg, ip FROM audit WHERE ts >= ? ORDER BY id DESC`,
        daysCut
      ).toArray();
      if (db.AUDIT_MAX && rows.length > db.AUDIT_MAX) rows = rows.slice(0, db.AUDIT_MAX);
      if (cat === 'fail') rows = rows.filter(r => !r.ok);
      else if (cat) rows = rows.filter(r => String(r.ev).startsWith(cat + '.'));
      const page = rows.filter(r => r.id < before).slice(0, limit);
      return json(200, {
        events: page,
        total: rows.length,
        nextBefore: page.length === limit ? page[page.length - 1].id : null,
        enabled: db.AUDIT_ON, ip_mode: String(db.env.AUDIT_IP || '').trim().toLowerCase(),
        retention: { max: db.AUDIT_MAX, days: db.AUDIT_DAYS },
        now: Date.now()
      });
    },

    // Deleting the log is itself logged, and auditSeq is not reset — so a clear always leaves a
    // visible gap in the ids and can't be used to quietly erase a trace.
    'POST /api/admin/audit/clear': async function (request) {
      const a = requireAdmin(request); if (a.answer) return a.answer;
      db.sql.exec(`DELETE FROM audit`);
      audit(request, 'admin.audit.clear', { user: a.user });
      return json(200, { ok: true });
    }
  };
}
