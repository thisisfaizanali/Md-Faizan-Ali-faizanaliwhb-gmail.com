// Sessions: start (compound check + exclusivity), list, read, end.

import { send, notFound, conflict, deviceBusy, badRequest } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { snapshotAuthority, sessionExpiry, sweepExpired } from '../lifecycle.js';
import { audit } from '../audit.js';
import { visibleDevice } from './devices.js';
import { queryInt } from './orgs.js';

const sessionOut = (row) => ({ ...row, authorized_by: JSON.parse(row.authorized_by) });

// Scoped by the caller's org in the WHERE: another org's session does not exist here.
function sessionOr404(db, orgId, id) {
  sweepExpired(db, { orgId, sessionId: id });
  const s = db.prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?').get(id, orgId);
  if (!s) throw notFound();
  return s;
}

export function registerSessionRoutes(r, { db }) {
  r.post('/v1/orgs/:org/sessions', (ctx, _p, res) => {
    const { deviceId, mode } = ctx.body;
    if (typeof deviceId !== 'string') throw badRequest('deviceId is required');
    const device = visibleDevice(db, ctx.orgId, deviceId);
    assertCanStartSession(db, ctx, mode, device.id);

    const id = newId('ses');
    const startedAt = nowIso();
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id }, mode);
    try {
      db.transaction(() => {
        sweepExpired(db, { orgId: ctx.orgId, deviceId: device.id });
        // The partial unique index decides exclusivity; no check-then-insert.
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?,?,?,?,?,'active',?,?,?)`
        ).run(id, ctx.orgId, ctx.userId, device.id, mode, JSON.stringify(authorizedBy), startedAt,
              sessionExpiry(db, ctx.orgId, startedAt));
        audit(db, ctx, { action: 'session.start', targetType: 'session', targetId: id });
      })();
    } catch (err) {
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      const holder = db.prepare(
        "SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')"
      ).get(device.id);
      throw deviceBusy(`device already has an exclusive session (held by ${holder?.id ?? 'another session'})`);
    }
    send(res, 201, sessionOut(db.prepare('SELECT * FROM sessions WHERE id = ?').get(id)));
  });

  r.get('/v1/orgs/:org/sessions', (ctx, _p, res) => {
    assertCan(db, ctx, 'session:view');
    const limit = queryInt(ctx.query, 'limit', 50, 1, 500);
    const offset = queryInt(ctx.query, 'offset', 0, 0, Number.MAX_SAFE_INTEGER);
    sweepExpired(db, { orgId: ctx.orgId });
    const rows = db.prepare(
      'SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?'
    ).all(ctx.orgId, limit, offset);
    send(res, 200, { sessions: rows.map(sessionOut), limit, offset });
  });

  r.get('/v1/sessions/:id', (ctx, p, res) => {
    const s = sessionOr404(db, ctx.orgId, p.id);
    if (s.user_id !== ctx.userId) assertCan(db, ctx, 'session:view');
    send(res, 200, sessionOut(s));
  });

  r.delete('/v1/sessions/:id', (ctx, p, res) => {
    const s = sessionOr404(db, ctx.orgId, p.id);
    if (s.state === 'ended') throw conflict('session already ended');
    let reason = 'user_stopped';
    if (s.user_id !== ctx.userId) {
      assertCan(db, ctx, 'session:terminate');
      reason = 'admin_terminated';
    }
    db.transaction(() => {
      const { changes } = db.prepare(
        "UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state <> 'ended'"
      ).run(reason, nowIso(), s.id);
      if (changes !== 1) throw conflict('session already ended');
      audit(db, ctx, { action: 'session.end', targetType: 'session', targetId: s.id, reasonCode: reason });
    })();
    send(res, 200, sessionOut(db.prepare('SELECT * FROM sessions WHERE id = ?').get(s.id)));
  });
}
