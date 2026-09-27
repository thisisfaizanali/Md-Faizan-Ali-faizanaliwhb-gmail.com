// /v1/auth/*: login, refresh (rotating, family-revoking), logout, org switch, me.

import { randomUUID } from 'node:crypto';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';
import { nowIso } from '../db.js';
import {
  issueAccessToken, hashPassword, verifyPassword,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';

// Unknown emails still pay for one scrypt, so response time doesn't reveal the account.
const DUMMY_HASH = hashPassword(randomUUID());

// Shared with invite accept, so a wrong password reads the same everywhere.
export const badLogin = () => unauthenticated('invalid email or password');

const COOKIE = 'rt';
const COOKIE_ATTRS = 'HttpOnly; Secure; SameSite=Strict; Path=/v1/auth';

function readCookie(req) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}

export function issueRefresh(db, res, userId, familyId = randomUUID()) {
  const raw = newRefreshToken();
  db.prepare('INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)')
    .run(randomUUID(), userId, hashRefreshToken(raw), familyId,
         new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());
  res.setHeader('set-cookie', `${COOKIE}=${raw}; ${COOKIE_ATTRS}; Max-Age=${REFRESH_TTL_SECONDS}`);
}

const activeMemberships = (db, userId) =>
  db.prepare(
    `SELECT m.org_id, m.role, m.perm_version, o.name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.user_id = ? AND m.status = 'active'
      ORDER BY m.joined_at IS NULL, m.joined_at, m.created_at`
  ).all(userId);

// The one response shape for login / refresh / token / me.
function authShape(db, userId, orgId) {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
  const orgs = activeMemberships(db, userId);
  const cur = orgs.find((o) => o.org_id === orgId);
  return {
    user,
    org: { id: cur.org_id, name: cur.name, theme: cur.theme },
    role: cur.role,
    orgs: orgs.map((o) => ({ id: o.org_id, name: o.name, theme: o.theme, role: o.role })),
    permissions: resolve(db, { userId, orgId }).permissions,
  };
}

export function withToken(db, secret, userId, orgId) {
  const shape = authShape(db, userId, orgId);
  const pv = db.prepare('SELECT perm_version FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId).perm_version;
  const token = issueAccessToken({ userId, orgId, role: shape.role, permVersion: pv }, secret);
  return { token, ...shape };
}

function firstActiveOrg(db, userId) {
  const first = activeMemberships(db, userId)[0];
  if (!first) throw forbidden('no active membership', 'no_active_membership');
  return first.org_id;
}

export function registerAuthRoutes(r, { db, secret }) {
  r.post('/v1/auth/login', (ctx, _p, res) => {
    const email = String(ctx.body.email ?? '').trim().toLowerCase();
    const password = String(ctx.body.password ?? '');
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    const ok = verifyPassword(password, user?.password_hash ?? DUMMY_HASH);
    if (!user || !ok) throw badLogin();

    const active = activeMemberships(db, user.id);
    const orgId = active.some((m) => m.org_id === ctx.body.orgId) ? ctx.body.orgId : firstActiveOrg(db, user.id);
    issueRefresh(db, res, user.id);
    send(res, 200, withToken(db, secret, user.id, orgId));
  });

  r.post('/v1/auth/refresh', (ctx, _p, res) => {
    const raw = readCookie(ctx.req);
    const row = raw && db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row || row.expires_at <= nowIso()) throw unauthenticated('invalid refresh token');

    if (row.revoked_at) {
      // Replay of a rotated token: kill the whole lineage.
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(nowIso(), row.family_id);
      throw unauthenticated('invalid refresh token');
    }

    // Stay in the org the client asked for (a stale token in Globex must not refresh into
    // Acme); otherwise fall back to the earliest-joined active org.
    const wanted = ctx.body.orgId;
    const orgId = activeMemberships(db, row.user_id).some((m) => m.org_id === wanted) ? wanted : firstActiveOrg(db, row.user_id);
    db.transaction(() => {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), row.id);
      issueRefresh(db, res, row.user_id, row.family_id);
    })();
    send(res, 200, withToken(db, secret, row.user_id, orgId));
  });

  r.post('/v1/auth/logout', (ctx, _p, res) => {
    const raw = readCookie(ctx.req);
    const row = raw && db.prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (row) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(nowIso(), row.family_id);
    }
    res.setHeader('set-cookie', `${COOKIE}=; ${COOKIE_ATTRS}; Max-Age=0`);
    send(res, 204);
  });

  r.post('/v1/auth/token', (ctx, _p, res) => {
    const orgId = ctx.body.orgId;
    if (typeof orgId !== 'string') throw badRequest('orgId is required');
    const m = db.prepare(
      `SELECT m.status FROM memberships m JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
        WHERE m.org_id = ? AND m.user_id = ?`
    ).get(orgId, ctx.userId);
    if (m?.status === 'suspended') throw forbidden('membership suspended', 'suspended');
    if (m?.status !== 'active') throw notFound();
    send(res, 200, withToken(db, secret, ctx.userId, orgId));
  });

  r.get('/v1/auth/me', (ctx, _p, res) => {
    send(res, 200, authShape(db, ctx.userId, ctx.orgId));
  });
}
