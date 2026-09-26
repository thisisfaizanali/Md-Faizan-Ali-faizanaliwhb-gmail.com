// Devices and grants. A device is visible iff it is in the caller's org and not
// soft-deleted; anything else is a 404 with the same body as a device that never existed.

import { send, badRequest, forbidden, notFound, conflict, normalizeTs, HttpError } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, assertMayGrant, resolve, resolveDevices, resolveOrgWide, DEVICE_SCOPED_RESOURCES } from '../permissions.js';
import { assertCanModify, endActiveSessions } from '../lifecycle.js';
import { audit } from '../audit.js';

export function visibleDevice(db, orgId, id) {
  const d = db.prepare('SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(id, orgId);
  if (!d) throw notFound();
  return d;
}

const deviceOut = (d, permissions) =>
  ({ id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions });

const withPermissions = (db, ctx, d) =>
  deviceOut(d, resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: d.id }).permissions);

function deviceName(value) {
  const name = typeof value === 'string' ? value.trim() : '';
  if (name.length < 1 || name.length > 64) throw badRequest('name must be 1-64 characters', 'invalid_name');
  return name;
}

function assertNameFree(db, orgId, name, exceptId = null) {
  const taken = db.prepare(
    'SELECT 1 FROM devices WHERE org_id = ? AND name = ? AND deleted_at IS NULL AND id IS NOT ?'
  ).get(orgId, name, exceptId);
  if (taken) throw conflict('a device with this name already exists');
}

// Retire a device from an org: its sessions end and its device-scoped grants there are
// revoked, so a transfer back (or an undelete) cannot resurrect them.
function retireFromOrg(db, orgId, deviceId) {
  endActiveSessions(db, { orgId, deviceId, reason: 'device_transferred' });
  db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL')
    .run(nowIso(), orgId, deviceId);
}

// Grants in the list shape. One query, grouped here.
function listGrants(db, orgId, { userId = null, grantId = null } = {}) {
  const now = nowIso();
  const rows = db.prepare(
    `SELECT g.*, gp.permission FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.org_id = ? AND g.revoked_at IS NULL AND (? IS NULL OR g.user_id = ?) AND (? IS NULL OR g.id = ?)
      ORDER BY g.created_at, g.id, gp.permission`
  ).all(orgId, userId, userId, grantId, grantId);
  const byId = new Map();
  for (const r of rows) {
    if (!byId.has(r.id)) {
      const status = r.starts_at && now < r.starts_at ? 'scheduled'
        : r.expires_at && r.expires_at <= now ? 'expired' : 'active';
      byId.set(r.id, {
        id: r.id, userId: r.user_id, deviceId: r.device_id, effect: r.effect, permissions: [],
        startsAt: r.starts_at, expiresAt: r.expires_at, createdBy: r.created_by, createdAt: r.created_at, status,
      });
    }
    byId.get(r.id).permissions.push(r.permission);
  }
  return [...byId.values()];
}

// A pattern may be device-scoped if it is '<r>:*' or a key, with r a device-scoped resource.
// Unknown keys are left for the foreign key to reject as unknown_permission.
function assertDeviceScopable(db, patterns) {
  const resourceOf = db.prepare('SELECT resource FROM permissions WHERE key = ?');
  for (const p of patterns) {
    const resource = p.endsWith(':*') ? p.slice(0, -2) : p === '*' ? null : resourceOf.get(p)?.resource;
    if (resource === undefined) continue;
    if (!DEVICE_SCOPED_RESOURCES.includes(resource)) {
      throw badRequest(`${p} cannot be scoped to a device`, 'scope_mismatch');
    }
  }
}

export function registerDeviceRoutes(r, { db }) {
  r.get('/v1/orgs/:org/devices', (ctx, _p, res) => {
    assertCan(db, ctx, 'device:list');
    const rows = db.prepare('SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name').all(ctx.orgId);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: rows.map((d) => d.id) });
    // device:view decides row inclusion: a denied row is absent, never redacted.
    const devices = rows
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => deviceOut(d, byDevice[d.id]));
    send(res, 200, { devices });
  });

  r.get('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const d = visibleDevice(db, ctx.orgId, p.id);
    assertCan(db, ctx, 'device:view', d.id);
    send(res, 200, withPermissions(db, ctx, d));
  });

  r.post('/v1/orgs/:org/devices', (ctx, _p, res) => {
    assertCan(db, ctx, 'device:provision');
    const name = deviceName(ctx.body.name);
    const { kind, online = false } = ctx.body;
    if (typeof kind !== 'string') throw badRequest('kind is required', 'invalid_kind');
    if (typeof online !== 'boolean') throw badRequest('online must be a boolean');
    const id = newId('dev');
    try {
      db.transaction(() => {
        assertNameFree(db, ctx.orgId, name);
        db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?,?,?,?,?)')
          .run(id, ctx.orgId, name, kind, online ? 1 : 0);
        audit(db, ctx, { action: 'device.create', targetType: 'device', targetId: id });
      })();
    } catch (err) {
      // The kind list lives in the schema's CHECK, not here.
      if (err.code === 'SQLITE_CONSTRAINT_CHECK') throw badRequest('unknown device kind', 'invalid_kind');
      throw err;
    }
    send(res, 201, withPermissions(db, ctx, visibleDevice(db, ctx.orgId, id)));
  });

  r.patch('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const d = visibleDevice(db, ctx.orgId, p.id);
    assertCan(db, ctx, 'device:update', d.id);
    const name = deviceName(ctx.body.name);
    db.transaction(() => {
      assertNameFree(db, ctx.orgId, name, d.id);
      db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name, d.id);
      audit(db, ctx, { action: 'device.update', targetType: 'device', targetId: d.id });
    })();
    send(res, 200, withPermissions(db, ctx, visibleDevice(db, ctx.orgId, d.id)));
  });

  r.delete('/v1/orgs/:org/devices/:id', (ctx, p, res) => {
    const d = visibleDevice(db, ctx.orgId, p.id);
    assertCan(db, ctx, 'device:provision', d.id);
    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), d.id);
      retireFromOrg(db, ctx.orgId, d.id);
      audit(db, ctx, { action: 'device.delete', targetType: 'device', targetId: d.id });
    })();
    send(res, 204);
  });

  r.post('/v1/orgs/:org/devices/:id/transfer', (ctx, p, res) => {
    const d = visibleDevice(db, ctx.orgId, p.id);
    assertCan(db, ctx, 'device:provision', d.id);
    const { toOrgId } = ctx.body;
    if (typeof toOrgId !== 'string' || toOrgId === ctx.orgId) throw badRequest('toOrgId must be another org');
    const member = db.prepare(
      `SELECT 1 FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
        WHERE m.org_id = ? AND m.user_id = ? AND m.status = 'active'`
    ).get(toOrgId, ctx.userId);
    if (!member) throw notFound();
    // Strictly org-wide: provision on one device there is not authority to receive into the org.
    const there = resolveOrgWide(db, { userId: ctx.userId, orgId: toOrgId }).permissions['device:provision'];
    if (there.effect !== 'allow') throw forbidden('missing permission device:provision in the target org', 'missing_permission');

    db.transaction(() => {
      retireFromOrg(db, ctx.orgId, d.id);
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(toOrgId, d.id);
      audit(db, ctx, { action: 'device.transfer_out', targetType: 'device', targetId: d.id });
      audit(db, { ...ctx, orgId: toOrgId }, { action: 'device.transfer_in', targetType: 'device', targetId: d.id });
    })();
    send(res, 200, { id: d.id, orgId: toOrgId });
  });

  r.post('/v1/orgs/:org/grants', (ctx, _p, res) => {
    assertCan(db, ctx, 'grant:create');
    const { permissions, effect, userId, deviceId = null } = ctx.body;
    if (!Array.isArray(permissions) || permissions.length === 0 || !permissions.every((x) => typeof x === 'string')) {
      throw badRequest('permissions must be a non-empty array of strings');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest("effect must be 'allow' or 'deny'");
    if (typeof userId !== 'string') throw badRequest('userId is required');
    if (deviceId !== null && typeof deviceId !== 'string') throw badRequest('deviceId must be a string');

    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt && expiresAt <= nowIso()) throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is not in the future');
    if (startsAt && expiresAt && startsAt >= expiresAt) throw badRequest('startsAt must be before expiresAt');

    if (userId === ctx.userId) throw forbidden('you cannot grant to yourself', 'self_grant');
    const target = db.prepare(
      "SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'"
    ).get(ctx.orgId, userId);
    if (!target) throw notFound();
    assertCanModify(db, ctx, target);

    const patterns = [...new Set(permissions)];
    if (deviceId !== null) {
      visibleDevice(db, ctx.orgId, deviceId);
      assertDeviceScopable(db, patterns);
    }
    assertMayGrant(db, ctx, patterns, deviceId);

    const id = newId('grt');
    try {
      db.transaction(() => {
        db.prepare(
          'INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?)'
        ).run(id, ctx.orgId, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
        const add = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?,?)');
        for (const p of patterns) add.run(id, p);
        bumpPermVersion(db, { orgId: ctx.orgId, userId });
        audit(db, ctx, { action: 'grant.create', targetType: 'grant', targetId: id });
      })();
    } catch (err) {
      // D19: the foreign key rejects anything that is not a permission or pattern.
      if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') throw badRequest('unknown permission', 'unknown_permission');
      throw err;
    }
    send(res, 201, listGrants(db, ctx.orgId, { grantId: id })[0]);
  });

  r.get('/v1/orgs/:org/grants', (ctx, _p, res) => {
    assertCan(db, ctx, 'user:read');
    send(res, 200, { grants: listGrants(db, ctx.orgId, { userId: ctx.query.get('userId') }) });
  });

  r.delete('/v1/orgs/:org/grants/:id', (ctx, p, res) => {
    assertCan(db, ctx, 'grant:revoke');
    const g = db.prepare('SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(p.id, ctx.orgId);
    if (!g) throw notFound();
    // Revoking a deny on yourself is self-escalation.
    if (g.user_id === ctx.userId) throw forbidden('you cannot revoke a grant on yourself', 'self_grant');
    const target = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, g.user_id);
    if (!target) throw notFound();
    assertCanModify(db, ctx, target);
    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), g.id);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: g.user_id });
      audit(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: g.id });
    })();
    send(res, 204);
  });
}
