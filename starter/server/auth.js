// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is the hand-out's;
// `verifyAccessToken` below is the verifier. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and listed above verifyAccessToken.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// verifyAccessToken returns the claims, or throws 401 UNAUTHENTICATED for:
//   1. anything but three dot-separated segments
//   2. a header or payload that is not base64url-encoded JSON
//   3. a header with `alg` other than HS256 or `typ` other than JWT
//   4. a signature mismatch (canonical base64url, constant-time compare)
//   5. an `exp` that is missing, not a number, or <= now
//   6. an `iss` or `aud` that is not ours
//   7. a missing or empty `jti`
// ---------------------------------------------------------------------------
const B64URL = /^[A-Za-z0-9_-]+$/;

// Decode one base64url segment to a plain JSON object, or null. Buffer's decoder
// silently skips invalid characters, so the alphabet is checked first.
function decodeObject(seg) {
  if (!B64URL.test(seg)) return null;
  try {
    const v = JSON.parse(unb64(seg).toString('utf8'));
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

export function verifyAccessToken(token, secret) {
  if (typeof token !== 'string') throw unauthenticated('missing token');
  const parts = token.split('.');
  if (parts.length !== 3) throw unauthenticated('malformed token');
  const [h, p, s] = parts;

  // The header is read only to reject; key and algorithm are fixed here.
  const header = decodeObject(h);
  if (!header) throw unauthenticated('malformed token');
  if (header.alg !== ALG || header.typ !== 'JWT') throw unauthenticated('unsupported token algorithm');

  // Signature before claims. Comparing the canonical encodings also rejects
  // non-canonical base64url spellings of the same bytes.
  const expected = Buffer.from(b64(createHmac('sha256', secret).update(`${h}.${p}`).digest()));
  const actual = Buffer.from(s);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw unauthenticated('invalid token signature');
  }

  const claims = decodeObject(p);
  if (!claims) throw unauthenticated('malformed token');
  if (!Number.isFinite(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw unauthenticated('token expired');
  }
  if (claims.iss !== ISS || claims.aud !== AUD) throw unauthenticated('token not issued for this api');
  if (typeof claims.jti !== 'string' || claims.jti === '') throw unauthenticated('token has no id');
  return claims;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
