// Edge cases for auth, members and audit that check-api.js does not reach.
// Same harness as check-api.js: spawn the server against a throwaway database.
//
//   node scripts/check-edges.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';

const PORT = 8124;
const BASE = `http://localhost:${PORT}/v1`;
const DB = join(tmpdir(), 'remoteops-check-edges.db');

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'test-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

await new Promise((r) => setTimeout(r, 1200));

for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, (err) => {
    console.error(`\n  aborted: ${err?.message ?? err}`);
    server.kill();
    process.exit(1);
  });
}

// Read-only peek at server state the API does not expose yet (sessions, grants).
const db = openDatabase(DB);

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, body: json, setCookie: res.headers.get('set-cookie') };
}

const login = (email, password = 'demo1234') => call('POST', '/auth/login', { body: { email, password } });
const cookieOf = (r) => r.setCookie?.split(';')[0] ?? null;
const withoutRequestId = (b) => ({ ...b?.error, requestId: undefined });

// ---------------------------------------------------------------------------
console.log('\n== login: no account enumeration ==');
const unknown = await login('nobody@example.test', 'whatever');
const wrongPw = await login('dana@example.test', 'whatever');
check('unknown email -> 401', unknown.status, 401);
check('wrong password -> 401', wrongPw.status, 401);
check('  ...bodies identical (minus requestId)', withoutRequestId(unknown.body), withoutRequestId(wrongPw.body));
check('email is trimmed and lowercased', (await login('  DANA@Example.TEST ')).status, 200);

console.log('\n== refresh rotation and family revocation ==');
const dana = await login('dana@example.test');
check('refresh cookie attributes',
  /^rt=[^;]+; HttpOnly; Secure; SameSite=Strict; Path=\/v1\/auth; Max-Age=2592000$/.test(dana.setCookie ?? ''), true);
const c1 = cookieOf(dana);
const r1 = await call('POST', '/auth/refresh', { cookie: c1 });
check('refresh -> 200', r1.status, 200);
check('  ...returns the login shape', Object.keys(r1.body ?? {}).sort(), ['org', 'orgs', 'permissions', 'role', 'token', 'user']);
const c2 = cookieOf(r1);
check('  ...rotates the cookie', c2 !== null && c2 !== c1, true);
check('old cookie replayed -> 401', (await call('POST', '/auth/refresh', { cookie: c1 })).status, 401);
check('  ...and the new one is dead too (family revoked)', (await call('POST', '/auth/refresh', { cookie: c2 })).status, 401);

console.log('\n== logout survives a reload ==');
const d2 = await login('dana@example.test');
const out = await call('POST', '/auth/logout', { cookie: cookieOf(d2) });
check('logout -> 204', out.status, 204);
check('  ...clears the cookie', /^rt=;.*Max-Age=0/.test(out.setCookie ?? ''), true);
check('refresh after logout -> 401', (await call('POST', '/auth/refresh', { cookie: cookieOf(d2) })).status, 401);

console.log('\n== org switch ==');
const danaTok = dana.body.token;
check('token for an org with no membership -> 404', (await call('POST', '/auth/token', { token: danaTok, body: { orgId: 'org_nope' } })).status, 404);
const me = await call('GET', '/auth/me', { token: danaTok });
check('GET /auth/me -> 200, org Acme', [me.status, me.body?.org?.id], [200, 'org_acme']);

console.log('\n== D8 modification authority ==');
check('self role change -> SELF_ROLE_CHANGE',
  (await call('PATCH', '/orgs/org_acme/members/usr_dana', { token: danaTok, body: { role: 'admin' } })).body?.error?.code, 'SELF_ROLE_CHANGE');
check('owner promotes viewer to admin -> 200',
  (await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: danaTok, body: { role: 'admin' } })).status, 200);
const adminTok = (await login('admin@acme.test')).body.token;
check('admin -> admin role change -> 403',
  (await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: adminTok, body: { role: 'viewer' } })).status, 403);
check('admin confers owner -> 403',
  (await call('PATCH', '/orgs/org_acme/members/usr_sam', { token: adminTok, body: { role: 'owner' } })).status, 403);
check('unknown role -> 400',
  (await call('PATCH', '/orgs/org_acme/members/usr_sam', { token: danaTok, body: { role: 'wizard' } })).status, 400);
check('owner demotes another owner -> 200',
  (await call('PATCH', '/orgs/org_acme/members/usr_acme_owner', { token: danaTok, body: { role: 'admin' } })).status, 200);
check('not a member -> 404',
  (await call('PATCH', '/orgs/org_acme/members/usr_globex_owner', { token: danaTok, body: { role: 'viewer' } })).status, 404);

console.log('\n== last owner ==');
// Dana is now Acme's only owner. A demote of the last owner by someone else cannot be
// reached (only an owner may modify an owner), so it is exercised through leave.
check('last owner leaves -> 409 LAST_OWNER',
  (await call('DELETE', '/orgs/org_acme/members/me', { token: danaTok })).body?.error?.code, 'LAST_OWNER');

console.log('\n== suspension ends sessions ==');
const live = () => db.prepare('SELECT state, end_reason FROM sessions WHERE id = ?').get('ses_live_build_server');
check('seeded live session is active', live().state, 'active');
check('suspend sam -> 200', (await call('POST', '/orgs/org_acme/members/usr_sam/suspend', { token: danaTok })).status, 200);
check('  ...session ended, user_suspended', live(), { state: 'ended', end_reason: 'user_suspended' });
check('suspend again -> 409', (await call('POST', '/orgs/org_acme/members/usr_sam/suspend', { token: danaTok })).status, 409);
check('reinstate -> 200', (await call('DELETE', '/orgs/org_acme/members/usr_sam/suspend', { token: danaTok })).status, 200);

console.log('\n== removal revokes grants ==');
const liveGrants = () => db.prepare(
  "SELECT count(*) AS n FROM grants WHERE org_id = 'org_acme' AND user_id = 'usr_acme_viewer' AND revoked_at IS NULL").get().n;
check('viewer has live grants before removal', liveGrants() > 0, true);
check('remove member -> 204', (await call('DELETE', '/orgs/org_acme/members/usr_acme_viewer', { token: danaTok })).status, 204);
check('  ...every grant of theirs is revoked', liveGrants(), 0);
check('  ...and they are gone from members',
  (await call('GET', '/orgs/org_acme/members', { token: danaTok })).body.members.some((m) => m.userId === 'usr_acme_viewer'), false);
check('effective for a removed member -> 404',
  (await call('GET', '/orgs/org_acme/users/usr_acme_viewer/effective', { token: danaTok })).status, 404);

console.log('\n== audit ==');
for (const q of ['limit=0', 'limit=501', 'limit=abc', 'offset=-1', 'offset=1.5']) {
  check(`audit?${q} -> 400`, (await call('GET', `/orgs/org_acme/audit?${q}`, { token: danaTok })).status, 400);
}
const samTok = (await login('sam@example.test')).body.token;
check('operator reads audit -> 403', (await call('GET', '/orgs/org_acme/audit', { token: samTok })).status, 403);
const events = (await call('GET', '/orgs/org_acme/audit?limit=500', { token: danaTok })).body.events;
const denial = events.find((e) => e.result === 'deny' && e.actor_id === 'usr_sam');
check('  ...recorded as a deny row', denial && { action: denial.action, reason_code: denial.reason_code },
  { action: 'GET /v1/orgs/:org/audit', reason_code: 'missing_permission' });
check('successful mutations are audited', events.some((e) => e.action === 'member.suspend' && e.result === 'allow'), true);
check('no row carries a token', JSON.stringify(events).includes(danaTok.split('.')[2]), false);

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
db.close();
server.kill();
process.exit(fail === 0 ? 0 : 1);
