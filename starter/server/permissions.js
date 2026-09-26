// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { forbidden, badRequest } from './http.js';

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/permissions.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Everything resolution needs, in three statements regardless of how many devices are
// evaluated afterwards: membership, catalogue + role baseline, applicable grants.
function load(db, { userId, orgId, now }) {
  const nowIso = new Date(now).toISOString();
  const membership = db
    .prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);
  const catalogue = db
    .prepare(
      `SELECT p.key, p.resource, rp.role IS NOT NULL AS baseline
         FROM permissions p
         LEFT JOIN role_permissions rp ON rp.permission = p.key AND rp.role = ?
        ORDER BY p.key`
    )
    .all(membership?.role ?? null);

  if (!membership || membership.status !== 'active') {
    return { role: membership?.status === 'suspended' ? membership.role : null,
             denyAll: membership?.status === 'suspended' ? 'suspended' : 'not_a_member', catalogue };
  }

  // Unrevoked, already started (expired ones are kept for 'expired_grant'). A device-scoped
  // grant counts only while its device is live and still in this org.
  const rows = db
    .prepare(
      `SELECT g.id, g.device_id, g.effect, g.expires_at, gp.permission
         FROM grants g
         JOIN grant_permissions gp ON gp.grant_id = g.id
         LEFT JOIN devices d ON d.id = g.device_id AND d.org_id = g.org_id AND d.deleted_at IS NULL
        WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
          AND (g.starts_at IS NULL OR g.starts_at <= ?)
          AND (g.device_id IS NULL OR d.id IS NOT NULL)
        ORDER BY g.created_at, g.id`
    )
    .all(userId, orgId, nowIso);
  const grants = rows.map((r) => ({
    id: r.id, deviceId: r.device_id, effect: r.effect, pattern: r.permission,
    active: r.expires_at === null || nowIso < r.expires_at,
  }));
  return { role: membership.role, denyAll: null, catalogue, grants };
}

const covers = (pattern, perm) =>
  pattern === '*' || pattern === perm.key ||
  (pattern.endsWith(':*') && pattern.slice(0, -2) === perm.resource);

const allow = (source) => ({ effect: 'allow', source, reason: null });
const deny = (source, reason) => ({ effect: 'deny', source, reason });

// Steps 1-5 of PERMISSIONS.md §3 for one permission over the grants that apply.
function decide(perm, role, grants) {
  const hit = (effect, active) => grants.find((g) => g.effect === effect && g.active === active && covers(g.pattern, perm));
  let g;
  if ((g = hit('deny', true))) return deny(`grant:${g.id}`, 'explicit_deny');
  if (perm.baseline) return allow(`role:${role}`);
  if ((g = hit('allow', true))) return allow(`grant:${g.id}`);
  if ((g = hit('allow', false))) return deny(`grant:${g.id}`, 'expired_grant');
  return deny(null, 'implicit');
}

function evaluate(state, deviceId) {
  const permissions = {};
  if (state.denyAll) {
    for (const p of state.catalogue) permissions[p.key] = deny(null, state.denyAll);
    return { role: state.role, permissions };
  }
  const orgWide = state.grants.filter((g) => g.deviceId === null);

  if (deviceId !== null) {
    const applying = state.grants.filter((g) => g.deviceId === null || g.deviceId === deviceId);
    for (const p of state.catalogue) permissions[p.key] = decide(p, state.role, applying);
    return { role: state.role, permissions };
  }

  // Org-level: org-wide grants decide; if still not allowed (and not org-wide denied), an
  // active device-scoped allow on some device without a deny there for P lifts it.
  // Device-scoped denies never remove an org-level allow.
  for (const p of state.catalogue) {
    let r = decide(p, state.role, orgWide);
    if (r.effect === 'deny' && r.reason !== 'explicit_deny') {
      const lift = state.grants.find((g) =>
        g.deviceId !== null && g.effect === 'allow' && g.active && covers(g.pattern, p) &&
        !state.grants.some((d) => d.deviceId === g.deviceId && d.effect === 'deny' && d.active && covers(d.pattern, p)));
      if (lift) r = allow(`grant:${lift.id}`);
    }
    permissions[p.key] = r;
  }
  return { role: state.role, permissions };
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  return evaluate(load(db, { userId, orgId, now }), deviceId);
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const state = load(db, { userId, orgId, now });
  const byDevice = {};
  for (const id of deviceIds) byDevice[id] = evaluate(state, id).permissions;
  return { role: state.role, byDevice };
}

// Per-request memo only: ctx.resolved is a fresh Map per request (context.js).
function resolvedFor(db, ctx, deviceId = null) {
  const key = deviceId ?? null;
  const memo = ctx.resolved instanceof Map ? ctx.resolved : null;
  if (memo?.has(key)) return memo.get(key);
  const r = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: key });
  memo?.set(key, r);
  return r;
}

export function can(db, ctx, permission, deviceId) {
  return resolvedFor(db, ctx, deviceId).permissions[permission]?.effect === 'allow';
}

const FORBID_REASONS = new Set(['explicit_deny', 'expired_grant', 'suspended']);

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const r = resolvedFor(db, ctx, deviceId).permissions[permission];
  if (r?.effect === 'allow') return;
  const reason = FORBID_REASONS.has(r?.reason) ? r.reason : 'missing_permission';
  throw forbidden(`missing permission ${permission}`, reason);
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  throw todo('assertMayGrant');
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  if (!Object.hasOwn(MODE_PERMISSION, mode)) throw badRequest('unknown session mode');
  if (!can(db, ctx, 'session:start', deviceId)) {
    throw forbidden('missing permission session:start on this device', 'missing_permission');
  }
  const needed = MODE_PERMISSION[mode];
  if (!can(db, ctx, needed, deviceId)) {
    throw forbidden(`missing permission ${needed} on this device`, 'missing_device_permission');
  }
}
