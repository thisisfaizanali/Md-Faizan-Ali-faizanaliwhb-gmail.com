// Invites: the only way to add a person (AUTH-DATA-MODEL.md §6).

import { send, badRequest, notFound, conflict, gone } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan } from '../permissions.js';
import { assertCanAssign } from '../lifecycle.js';
import { audit } from '../audit.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { issueRefresh, withToken, badLogin } from './auth.js';

const INVITE_TTL_MS = 7 * 864e5;

function inviteEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (email.split('@').length !== 2 || email.length > 254) throw badRequest('invalid email', 'invalid_email');
  return email;
}

// Token -> live invite, or the refusal: unknown 404, accepted 409, revoked/expired/org gone 410.
function liveInvite(db, raw) {
  const inv = db.prepare(
    `SELECT i.*, o.name AS org_name, o.deleted_at AS org_deleted_at
       FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?`
  ).get(hashInviteToken(raw));
  if (!inv) throw notFound();
  if (inv.accepted_at) throw conflict('invite already accepted');
  if (inv.revoked_at || inv.expires_at <= nowIso() || inv.org_deleted_at) throw gone();
  return inv;
}

export function registerInviteRoutes(r, { db, secret }) {
  r.post('/v1/orgs/:org/invites', (ctx, _p, res) => {
    assertCan(db, ctx, 'user:invite');
    const email = inviteEmail(ctx.body.email);
    const role = ctx.body.role;
    assertCanAssign(db, ctx, role);

    const member = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active','suspended')`
    ).get(ctx.orgId, email);
    if (member) throw conflict('already a member of this org');

    const raw = newInviteToken();
    const id = newId('inv');
    const now = nowIso();
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    try {
      db.transaction(() => {
        // one_live_invite_per_email ignores expires_at, so an expired, unaccepted invite
        // would block this email forever. Retire it first, in the same transaction.
        db.prepare(
          `UPDATE invites SET revoked_at = ?
            WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= ?`
        ).run(now, ctx.orgId, email, now);
        db.prepare(
          'INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?,?,?,?,?,?,?)'
        ).run(id, ctx.orgId, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
        audit(db, ctx, { action: 'invite.create', targetType: 'invite', targetId: id });
      })();
    } catch (err) {
      // A live invite already exists: the unique index decides, not a check-then-insert.
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') throw conflict('a live invite already exists for this email');
      throw err;
    }
    send(res, 201, { id, email, role, expiresAt, inviteToken: raw });
  });

  r.get('/v1/orgs/:org/invites', (ctx, _p, res) => {
    assertCan(db, ctx, 'user:invite');
    const invites = db.prepare(
      `SELECT id, email, role,
              CASE WHEN expires_at <= ? THEN 'expired' ELSE 'pending' END AS status,
              expires_at AS expiresAt, created_at AS createdAt, invited_by AS invitedBy
         FROM invites
        WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
        ORDER BY created_at DESC, id`
    ).all(nowIso(), ctx.orgId);
    send(res, 200, { invites });
  });

  r.delete('/v1/orgs/:org/invites/:id', (ctx, p, res) => {
    assertCan(db, ctx, 'user:invite');
    db.transaction(() => {
      const { changes } = db.prepare(
        'UPDATE invites SET revoked_at = ? WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL'
      ).run(nowIso(), p.id, ctx.orgId);
      if (changes !== 1) throw notFound();
      audit(db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: p.id });
    })();
    send(res, 204);
  });

  r.get('/v1/invites/:token', (_ctx, p, res) => {
    const inv = liveInvite(db, p.token);
    send(res, 200, { orgName: inv.org_name, role: inv.role, email: inv.email, expiresAt: inv.expires_at });
  });

  r.post('/v1/invites/:token/accept', (ctx, p, res) => {
    const inv = liveInvite(db, p.token);
    const existing = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(inv.email);
    const password = String(ctx.body.password ?? '');

    let name;
    if (existing) {
      // Holding an invite must not sign you in as someone else: prove the account.
      if (!verifyPassword(password, existing.password_hash)) throw badLogin();
    } else {
      name = typeof ctx.body.name === 'string' ? ctx.body.name.trim() : '';
      if (name.length < 1 || name.length > 80) throw badRequest('name must be 1-80 characters', 'invalid_name');
      if (password.length < 8) throw badRequest('password must be at least 8 characters', 'invalid_password');
    }
    const passwordHash = existing ? null : hashPassword(password); // scrypt outside the transaction

    const userId = existing?.id ?? newId('usr');
    db.transaction(() => {
      const now = nowIso();
      if (!existing) {
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)')
          .run(userId, inv.email, name, passwordHash);
      }
      // The conditional update is the single-winner guarantee for concurrent accepts.
      const { changes } = db.prepare(
        `UPDATE invites SET accepted_at = ?, accepted_by = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`
      ).run(now, userId, inv.id, now);
      if (changes !== 1) throw conflict('invite already accepted');

      const m = db.prepare('SELECT id, status FROM memberships WHERE org_id = ? AND user_id = ?').get(inv.org_id, userId);
      if (!m) {
        db.prepare(
          "INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?,?,?,?,'active',?,?)"
        ).run(newId('mem'), inv.org_id, userId, inv.role, inv.invited_by, now);
      } else if (m.status === 'removed' || m.status === 'invited') {
        db.prepare("UPDATE memberships SET role = ?, status = 'active', joined_at = ? WHERE id = ?").run(inv.role, now, m.id);
        bumpPermVersion(db, { orgId: inv.org_id, userId });
      } else {
        throw conflict('already a member of this org');
      }
      audit(db, { ...ctx, userId, orgId: inv.org_id }, { action: 'invite.accept', targetType: 'invite', targetId: inv.id });
    })();

    issueRefresh(db, res, userId);
    send(res, 200, withToken(db, secret, userId, inv.org_id));
  });
}
