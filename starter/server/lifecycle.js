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
import { resolve, MODE_PERMISSION } from './permissions.js';

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
  if (isRoleChange) assertCanAssign(db, ctx, newRole);
}

// Roles the caller may confer (role change or invite): owner only by an owner, and never
// above the caller's own rank.
export function assertCanAssign(db, ctx, role) {
  assertRoleExists(db, role);
  if (role === OWNER && ctx.role !== OWNER) throw forbidden('only an owner can confer owner', 'rank');
  if (!mayAssign(roleRanks(db), ctx.role, role)) throw forbidden('you cannot assign a role above your own', 'rank');
}

const mayAssign = (ranks, callerRole, role) =>
  (role !== OWNER || callerRole === OWNER) && ranks[role] <= ranks[callerRole];

// The same rule as a list, for the console: it must never know role names or ranks itself.
export function assignableRoles(db, callerRole) {
  const roles = db.prepare('SELECT key, rank, label FROM roles ORDER BY rank DESC').all();
  const ranks = Object.fromEntries(roles.map((r) => [r.key, r.rank]));
  return roles.filter((r) => mayAssign(ranks, callerRole, r.key)).map(({ key, label }) => ({ key, label }));
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

// The authority a session starts with, frozen (PERMISSIONS.md §7.1): the role, and the grants
// behind session:start and the mode permission on that device. Same shape as the seed.
export function snapshotAuthority(db, { userId, orgId, deviceId }, mode) {
  const snapshotAt = nowIso();
  const { role, permissions } = resolve(db, { userId, orgId, deviceId, now: new Date(snapshotAt) });
  const grantIds = [...new Set(['session:start', MODE_PERMISSION[mode]]
    .map((k) => permissions[k]?.source)
    .filter((src) => src?.startsWith('grant:'))
    .map((src) => src.slice('grant:'.length)))];
  return { role, grantIds, snapshotAt };
}

export function sessionExpiry(db, orgId, now = new Date()) {
  const { max_session_minutes: minutes } = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  return new Date(new Date(now).getTime() + minutes * 6e4).toISOString();
}

// one_exclusive_session_per_device knows nothing about expires_at: an expired control session
// holds the device until something ends it. Sweep before inserting and before any read.
export function sweepExpired(db, { orgId, deviceId = null, sessionId = null }) {
  const now = nowIso();
  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE org_id = ? AND state = 'active' AND expires_at <= ?
        AND (? IS NULL OR device_id = ?) AND (? IS NULL OR id = ?)`
  ).run(now, orgId, now, deviceId, deviceId, sessionId, sessionId).changes;
}
