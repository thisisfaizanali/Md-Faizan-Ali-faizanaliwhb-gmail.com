// Append-only audit writes.
//
// YOURS TO WRITE. This file ships as a stub.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Two things the spec is explicit about (BRIEF.md §4, PERMISSIONS.md §8):
//
//   - DENIED attempts are recorded, not just successes. A log that only holds
//     successes cannot answer "who tried to change what".
//   - a single action produces a single row. Write the success row inside the same
//     transaction as the change it describes; do not also log the allow from a wrapper.
//
// Schema columns: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
// result ('allow'|'deny'), reason_code, request_id, at.

import { newId } from './db.js';
import { HttpError } from './http.js';

// One row. orgId defaults to the caller's org (org creation passes the new org's id).
// Never pass a token, password or cookie in any field.
export function audit(db, ctx, { orgId = ctx.orgId, action, targetType = null, targetId = null, result = 'allow', reasonCode = null }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(newId('aud'), orgId, ctx.userId ?? null, action, targetType, targetId, result, reasonCode, ctx.requestId ?? null);
}

// Run fn(); if it refuses with a 403 in a known org, record the denial before rethrowing.
export async function auditDenials(db, ctx, meta, fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403 && ctx.orgId) {
      audit(db, ctx, { ...meta, result: 'deny', reasonCode: err.reason });
    }
    throw err;
  }
}
