// /v1/orgs: orgs, members, effective permissions, audit.

import { send, badRequest, notFound, conflict } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, resolve } from '../permissions.js';
import { OWNER, assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions } from '../lifecycle.js';
import { audit } from '../audit.js';

const THEMES = ['cobalt', 'ember', 'jade', 'violet', 'amber', 'slate'];

function orgName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (name.length < 1 || name.length > 80) throw badRequest('name must be 1-80 characters', 'invalid_name');
  return name;
}

// A strict non-negative integer from a query string; anything else is a 400, never clamped.
export function queryInt(query, key, fallback, min, max) {
  const raw = query.get(key);
  if (raw === null) return fallback;
  const n = /^\d+$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= min && n <= max)) throw badRequest(`${key} must be an integer from ${min} to ${max}`, 'invalid_pagination');
  return n;
}

// The target's membership, if they are a member at all (active or suspended).
function memberOr404(db, orgId, userId) {
  const m = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
  if (!m || (m.status !== 'active' && m.status !== 'suspended')) throw notFound();
  return m;
}

// Membership removal (remove and leave): status, pv, sessions, and the user's grants —
// otherwise a later re-invite reusing the UNIQUE(org_id,user_id) row would resurrect them.
function removeMember(db, ctx, userId, action) {
  db.transaction(() => {
    assertNotLastOwner(db, ctx.orgId, userId);
    db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?").run(ctx.orgId, userId);
    bumpPermVersion(db, { orgId: ctx.orgId, userId });
    endActiveSessions(db, { orgId: ctx.orgId, userId, reason: 'membership_removed' });
    db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL')
      .run(nowIso(), ctx.orgId, userId);
    audit(db, ctx, { action, targetType: 'user', targetId: userId });
  })();
}

export function registerOrgRoutes(r, { db }) {
  r.get('/v1/orgs', (ctx, _p, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
        WHERE m.user_id = ? AND m.status = 'active'
        ORDER BY m.joined_at IS NULL, m.joined_at, m.created_at`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  r.post('/v1/orgs', (ctx, _p, res) => {
    const name = orgName(ctx.body.name);
    const used = new Set(db.prepare(
      `SELECT o.theme FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.userId).map((r) => r.theme));
    // Palette wraps to the first theme once a user is in 6+ orgs.
    const theme = THEMES.find((t) => !used.has(t)) ?? THEMES[0];
    const id = newId('org');
    db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?,?,?)').run(id, name, theme);
      db.prepare(
        "INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?,?,?,?,'active',?)"
      ).run(newId('mem'), id, ctx.userId, OWNER, nowIso());
      audit(db, ctx, { orgId: id, action: 'org.create', targetType: 'org', targetId: id });
    })();
    send(res, 201, { id, name, theme, role: OWNER });
  });

  r.patch('/v1/orgs/:org', (ctx, _p, res) => {
    assertCan(db, ctx, 'org:update');
    const b = ctx.body;
    const sets = {};
    if (b.name !== undefined) sets.name = orgName(b.name);
    if (b.theme !== undefined) {
      if (!THEMES.includes(b.theme)) throw badRequest('unknown theme', 'invalid_theme');
      sets.theme = b.theme;
    }
    if (b.maxSessionMinutes !== undefined) {
      if (!Number.isInteger(b.maxSessionMinutes) || b.maxSessionMinutes < 1 || b.maxSessionMinutes > 1440) {
        throw badRequest('maxSessionMinutes must be an integer from 1 to 1440', 'invalid_max_session_minutes');
      }
      sets.max_session_minutes = b.maxSessionMinutes;
    }
    if (Object.keys(sets).length === 0) throw badRequest('nothing to update');
    db.transaction(() => {
      const cols = Object.keys(sets); // fixed column names from above, never from input
      db.prepare(`UPDATE organizations SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`)
        .run(...cols.map((c) => sets[c]), ctx.orgId);
      audit(db, ctx, { action: 'org.update', targetType: 'org', targetId: ctx.orgId });
    })();
    const o = db.prepare('SELECT id, name, theme, max_session_minutes FROM organizations WHERE id = ?').get(ctx.orgId);
    send(res, 200, { id: o.id, name: o.name, theme: o.theme, maxSessionMinutes: o.max_session_minutes });
  });

  r.delete('/v1/orgs/:org', (ctx, _p, res) => {
    assertCan(db, ctx, 'org:delete');
    db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), ctx.orgId);
      endActiveSessions(db, { orgId: ctx.orgId, reason: 'admin_terminated' });
      audit(db, ctx, { action: 'org.delete', targetType: 'org', targetId: ctx.orgId });
    })();
    send(res, 204);
  });

  r.get('/v1/orgs/:org/members', (ctx, _p, res) => {
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT m.user_id AS userId, u.email, u.name, m.role, m.status, m.joined_at AS joinedAt
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active','suspended')
        ORDER BY m.joined_at IS NULL, m.joined_at, m.created_at`
    ).all(ctx.orgId);
    send(res, 200, { members });
  });

  // Registered before /members/:userId: first match wins.
  r.delete('/v1/orgs/:org/members/me', (ctx, _p, res) => {
    removeMember(db, ctx, ctx.userId, 'member.leave');
    send(res, 204);
  });

  r.patch('/v1/orgs/:org/members/:userId', (ctx, p, res) => {
    assertCan(db, ctx, 'user:role:update');
    const target = memberOr404(db, ctx.orgId, p.userId);
    const role = ctx.body.role;
    assertRoleExists(db, role); // a missing role is a 400, not "not a role change"
    assertCanModify(db, ctx, target, role);
    db.transaction(() => {
      if (role !== OWNER) assertNotLastOwner(db, ctx.orgId, target.user_id);
      db.prepare('UPDATE memberships SET role = ? WHERE id = ?').run(role, target.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
      audit(db, ctx, { action: 'member.role_update', targetType: 'user', targetId: target.user_id });
    })();
    send(res, 200, { userId: target.user_id, role });
  });

  r.post('/v1/orgs/:org/members/:userId/suspend', (ctx, p, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = memberOr404(db, ctx.orgId, p.userId);
    assertCanModify(db, ctx, target);
    if (target.status !== 'active') throw conflict('member is not active', 'CONFLICT');
    db.transaction(() => {
      assertNotLastOwner(db, ctx.orgId, target.user_id);
      db.prepare("UPDATE memberships SET status = 'suspended' WHERE id = ?").run(target.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
      endActiveSessions(db, { orgId: ctx.orgId, userId: target.user_id, reason: 'user_suspended' });
      audit(db, ctx, { action: 'member.suspend', targetType: 'user', targetId: target.user_id });
    })();
    send(res, 200, { userId: target.user_id, status: 'suspended' });
  });

  r.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, p, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = memberOr404(db, ctx.orgId, p.userId);
    assertCanModify(db, ctx, target);
    if (target.status !== 'suspended') throw conflict('member is not suspended', 'CONFLICT');
    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active' WHERE id = ?").run(target.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: target.user_id });
      audit(db, ctx, { action: 'member.reinstate', targetType: 'user', targetId: target.user_id });
    })();
    send(res, 200, { userId: target.user_id, status: 'active' });
  });

  r.delete('/v1/orgs/:org/members/:userId', (ctx, p, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = memberOr404(db, ctx.orgId, p.userId);
    assertCanModify(db, ctx, target);
    removeMember(db, ctx, target.user_id, 'member.remove');
    send(res, 204);
  });

  r.get('/v1/orgs/:org/users/:userId/effective', (ctx, p, res) => {
    if (p.userId !== ctx.userId) assertCan(db, ctx, 'user:read');
    memberOr404(db, ctx.orgId, p.userId);
    send(res, 200, resolve(db, { userId: p.userId, orgId: ctx.orgId }));
  });

  r.get('/v1/orgs/:org/audit', (ctx, _p, res) => {
    assertCan(db, ctx, 'audit:read');
    const limit = queryInt(ctx.query, 'limit', 50, 1, 500);
    const offset = queryInt(ctx.query, 'offset', 0, 0, Number.MAX_SAFE_INTEGER);
    const events = db.prepare(
      'SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC, rowid DESC LIMIT ? OFFSET ?'
    ).all(ctx.orgId, limit, offset);
    send(res, 200, { events, limit, offset });
  });
}
