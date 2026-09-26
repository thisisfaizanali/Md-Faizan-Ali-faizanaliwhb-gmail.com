// Per-request context: turn a bearer token into an authenticated caller.
//
// YOURS TO WRITE. This file ships as a stub so the server boots and every
// authenticated request fails loudly instead of appearing to work.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6):
//   - read the bearer token, verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that
//     names a different org is INVISIBLE — 404, never 403. Isolation is structural:
//     the caller cannot name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version (AUTH-DATA-MODEL.md §3), so a
//     role or grant change takes effect on the NEXT request, not at token expiry
//   - throw through the one error path in ./http.js
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries at
// least { userId, orgId, role, membership, claims }.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound, forbidden } from './http.js';

const BEARER = /^Bearer +([^\s]+)$/i;

export function authenticate(db, secret) {
  const findMembership = db.prepare(
    `SELECT m.* FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.org_id = ? AND m.user_id = ?`
  );

  return function buildContext(req, params) {
    const match = BEARER.exec(req.headers?.authorization ?? '');
    if (!match) throw unauthenticated('missing bearer token');
    const claims = verifyAccessToken(match[1], secret);

    // The token's org is the only one addressable; any other is invisible.
    if (params?.org !== undefined && params.org !== claims.org) throw notFound();

    const membership = findMembership.get(claims.org, claims.sub);
    if (!membership || membership.status === 'invited' || membership.status === 'removed') {
      throw unauthenticated('not a member of this org');
    }
    assertFresh(claims, membership);
    if (membership.status === 'suspended') throw forbidden('membership suspended', 'suspended');

    // Role from the row, never from claims.role.
    return { userId: claims.sub, orgId: claims.org, role: membership.role, membership, claims, resolved: new Map() };
  };
}
