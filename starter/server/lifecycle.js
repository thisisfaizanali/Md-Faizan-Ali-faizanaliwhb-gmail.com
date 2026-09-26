// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { forbidden, selfRoleChange, badRequest, lastOwner } from './http.js';
import { nowIso } from './db.js';

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/lifecycle.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

// The one role named in code: creator role, last-owner rule, "only owners confer owner".
export const OWNER = 'owner';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role)) {
    throw badRequest('unknown role', 'unknown_role');
  }
}

// D8 modification authority. `target` is the target's membership row; pass newRole only
// for a role change. Rank is modification authority only — never a can() answer.
export function assertCanModify(db, ctx, target, newRole) {
  const isRoleChange = newRole !== undefined;
  if (target.user_id === ctx.userId) {
    throw isRoleChange ? selfRoleChange() : forbidden('you cannot do this to yourself', 'self_modification');
  }
  const ranks = roleRanks(db);
  // An owner may modify another owner (check-api: owner demotes owner -> 200).
  if (!(ranks[ctx.role] > ranks[target.role] || ctx.role === OWNER)) {
    throw forbidden('you cannot modify a member of equal or higher role', 'rank');
  }
  if (isRoleChange) {
    assertRoleExists(db, newRole);
    if (newRole === OWNER && ctx.role !== OWNER) throw forbidden('only an owner can confer owner', 'rank');
    if (ranks[newRole] > ranks[ctx.role]) throw forbidden('you cannot assign a role above your own', 'rank');
  }
}

// Call inside the same transaction as the write that takes `userId` out of (active AND owner).
export function assertNotLastOwner(db, orgId, userId) {
  const m = db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (m?.role !== OWNER || m.status !== 'active') return;
  const { n } = db
    .prepare("SELECT count(*) AS n FROM memberships WHERE org_id = ? AND role = ? AND status = 'active'")
    .get(orgId, OWNER);
  if (n <= 1) throw lastOwner();
}

export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  return db
    .prepare(
      `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
        WHERE org_id = ? AND state IN ('connecting','active')
          AND (? IS NULL OR user_id = ?) AND (? IS NULL OR device_id = ?) AND (? IS NULL OR id <> ?)`
    )
    .run(reason, nowIso(), orgId, userId, userId, deviceId, deviceId, exceptSessionId, exceptSessionId).changes;
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) { throw todo('snapshotAuthority'); }
export function sessionExpiry(db, orgId) { throw todo('sessionExpiry'); }
