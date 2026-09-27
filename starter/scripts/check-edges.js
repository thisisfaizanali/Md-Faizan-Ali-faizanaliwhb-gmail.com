// Edge cases for auth, members and audit that check-api.js does not reach.
// Same harness as check-api.js: spawn the server against a throwaway database.
//
//   node scripts/check-edges.js

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDatabase } from '../server/db.js';
import { createRouter } from '../server/router.js';
import { registerRoutes } from '../server/routes/index.js';
import { authenticate } from '../server/context.js';
import { issueAccessToken, signToken } from '../server/auth.js';

const DB = join(tmpdir(), 'remoteops-check-edges.db');
const SECRET = 'test-secret';
let BASE, server, db, serverLog = '';

// Fresh seeded database + server. Sections that need the untouched fixture call it again.
async function boot(port) {
  for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
  execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });
  server = spawn(process.execPath, ['server/index.js'], {
    env: { ...process.env, DATABASE_FILE: DB, PORT: String(port), NODE_ENV: 'production', JWT_SECRET: SECRET },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  // Forwarded, and kept so the whole run can be scanned for unhandled errors at the end.
  server.stderr.on('data', (chunk) => { serverLog += chunk; process.stderr.write(chunk); });
  await new Promise((r) => setTimeout(r, 1200));
  BASE = `http://localhost:${port}/v1`;
  // Direct access to server state the API does not expose yet (sessions, grants).
  db = openDatabase(DB);
}
async function restart(port) {
  db.close();
  server.kill();
  await new Promise((r) => server.once('exit', r));
  await boot(port);
}

for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, (err) => {
    console.error(`
  aborted: ${err?.message ?? err}`);
    server?.kill();
    process.exit(1);
  });
}

await boot(8124);

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
check('  ...returns the login shape', Object.keys(r1.body ?? {}).sort(), ['assignableRoles', 'org', 'orgs', 'permissions', 'role', 'token', 'user']);
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

console.log('\n== refresh keeps the requested org ==');
const d3 = await login('dana@example.test');
const toGlobex = await call('POST', '/auth/refresh', { cookie: cookieOf(d3), body: { orgId: 'org_globex' } });
check('refresh {orgId: globex} -> Globex', [toGlobex.status, toGlobex.body?.org?.id], [200, 'org_globex']);
const toNope = await call('POST', '/auth/refresh', { cookie: cookieOf(toGlobex), body: { orgId: 'org_nope' } });
check('refresh {orgId: not a member} -> earliest org', [toNope.status, toNope.body?.org?.id], [200, 'org_acme']);

console.log('\n== org switch ==');
const danaTok = dana.body.token;
check('token for an org with no membership -> 404', (await call('POST', '/auth/token', { token: danaTok, body: { orgId: 'org_nope' } })).status, 404);
const me = await call('GET', '/auth/me', { token: danaTok });
check('GET /auth/me -> 200, org Acme', [me.status, me.body?.org?.id], [200, 'org_acme']);

console.log('\n== assignableRoles in the auth shape ==');
// Read from the roles table, so the personalised (undocumented) role is included.
const allRoles = db.prepare('SELECT key FROM roles ORDER BY key').all().map((r) => r.key);
check('owner may assign every role in the table', me.body.assignableRoles.map((r) => r.key).sort(), allRoles);
const adminShape = (await login('admin@acme.test')).body;
const adminRank = db.prepare("SELECT rank FROM roles WHERE key = 'admin'").get().rank;
check('admin gets no owner, nothing above admin',
  adminShape.assignableRoles.map((r) => r.key).sort(),
  db.prepare("SELECT key FROM roles WHERE rank <= ? AND key <> 'owner' ORDER BY key").all(adminRank).map((r) => r.key));

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
check('role change with no role -> 400',
  (await call('PATCH', '/orgs/org_acme/members/usr_sam', { token: danaTok, body: {} })).status, 400);
check('role change to role nope -> 400',
  (await call('PATCH', '/orgs/org_acme/members/usr_sam', { token: danaTok, body: { role: 'nope' } })).status, 400);
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

console.log('\n== invites ==');
const invite = (email, role = 'operator', token = danaTok) =>
  call('POST', '/orgs/org_acme/invites', { token, body: { email, role } });
const accept = (raw, body) => call('POST', `/invites/${raw}/accept`, { body });

const inv1 = await invite('  Invitee.One@Example.TEST ');
check('invite -> 201', inv1.status, 201);
const raw1 = inv1.body.inviteToken;
const peek1 = await call('GET', `/invites/${raw1}`);
check('peek -> 200 with exactly 4 keys', [peek1.status, Object.keys(peek1.body).sort()],
  [200, ['email', 'expiresAt', 'orgName', 'role']]);
check('the raw token is not in the database',
  db.prepare('SELECT count(*) AS n FROM invites WHERE instr(id || token_hash || email, ?) > 0').get(raw1).n, 0);
check('double invite of the same email -> 409', (await invite('invitee.one@example.test')).status, 409);
check('invite an existing active member -> 409', (await invite('sam@example.test')).status, 409);
check('admin invites owner -> 403', (await invite('owner.wannabe@example.test', 'owner', adminTok)).status, 403);
check('bad email -> 400', (await invite('no-at-sign')).status, 400);

const inv2 = await invite('revoke.me@example.test');
check('revoke -> 204', (await call('DELETE', `/orgs/org_acme/invites/${inv2.body.id}`, { token: danaTok })).status, 204);
check('  ...then peek -> 410', (await call('GET', `/invites/${inv2.body.inviteToken}`)).status, 410);
check('  ...revoke again -> 404', (await call('DELETE', `/orgs/org_acme/invites/${inv2.body.id}`, { token: danaTok })).status, 404);

const inv3 = await invite('expire.me@example.test');
db.prepare('UPDATE invites SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), inv3.body.id);
check('expired invite: peek -> 410', (await call('GET', `/invites/${inv3.body.inviteToken}`)).status, 410);
const listed = (await call('GET', '/orgs/org_acme/invites', { token: danaTok })).body.invites;
check('  ...listed as expired, no token_hash',
  [listed.find((i) => i.id === inv3.body.id)?.status, JSON.stringify(listed).includes('token')], ['expired', false]);
check('  ...re-invite the same email -> 201', (await invite('expire.me@example.test')).status, 201);

const acc1 = await accept(raw1, { name: 'Invitee One', password: 'longenough1' });
check('accept -> 200 with the login shape', [acc1.status, acc1.body?.role, acc1.body?.org?.id], [200, 'operator', 'org_acme']);
check('  ...sets the refresh cookie', /^rt=[^;]+;/.test(acc1.setCookie ?? ''), true);
check('accept again -> 409', (await accept(raw1, { name: 'X', password: 'longenough1' })).status, 409);

const inv4 = await invite('race@example.test');
const race = await Promise.all([1, 2].map(() => accept(inv4.body.inviteToken, { name: 'Racer', password: 'longenough1' })));
check('two parallel accepts -> one 200, one 409', race.map((x) => x.status).sort(), [200, 409]);

console.log('\n== re-invite a removed member (existing user) ==');
// usr_acme_viewer was removed above, with their grants revoked.
const viewerName = db.prepare("SELECT name FROM users WHERE id = 'usr_acme_viewer'").get().name;
const inv5 = await invite('viewer@acme.test', 'operator');
check('re-invite removed member -> 201', inv5.status, 201);
check('existing user, wrong password -> 401', (await accept(inv5.body.inviteToken, { name: 'Hijack', password: 'wrongpass1' })).status, 401);
const acc5 = await accept(inv5.body.inviteToken, { name: 'Ignored', password: 'demo1234' });
check('existing user, right password -> 200, same user', [acc5.status, acc5.body?.user?.id], [200, 'usr_acme_viewer']);
check('  ...one users row, name untouched',
  db.prepare("SELECT count(*) AS n, max(name) AS name FROM users WHERE email = 'viewer@acme.test'").get(),
  { n: 1, name: viewerName });
check('  ...membership active with the invite role',
  db.prepare("SELECT status, role FROM memberships WHERE org_id = 'org_acme' AND user_id = 'usr_acme_viewer'").get(),
  { status: 'active', role: 'operator' });
check('  ...old grants stay revoked', liveGrants(), 0);

// ===========================================================================
// Devices and grants, against a fresh fixture (earlier sections removed the viewer
// and ended the seeded session).
await restart(8125);
console.log('\n== Devices and grants: device list and visibility (fresh fixture) ==');
const tokOf = async (email) => (await login(email)).body.token;
const dana5 = await tokOf('dana@example.test');
const viewer5 = await tokOf('viewer@acme.test');
const vList = await call('GET', '/orgs/org_acme/devices', { token: viewer5 });
check('viewer list excludes kiosk-lobby-01', vList.body.devices.map((d) => d.id).includes('dev_kiosk_lobby_01'), false);
check('  ...every row carries permissions', vList.body.devices.every((d) => d.permissions && d.permissions['device:view']), true);
const danaGx = (await call('POST', '/auth/token', { token: dana5, body: { orgId: 'org_globex' } })).body.token;
const gx = (await call('GET', '/orgs/org_globex/devices', { token: danaGx })).body.devices;
check('dana in Globex: globex-desk-01 control allow', gx.find((d) => d.name === 'globex-desk-01').permissions['device:control'].effect, 'allow');
check('device in another org -> 404', (await call('GET', '/orgs/org_acme/devices/dev_globex_desk_01', { token: dana5 })).status, 404);
const kiosk = await call('GET', '/orgs/org_acme/devices/dev_kiosk_lobby_01', { token: viewer5 });
check('viewer GET kiosk-lobby-01 -> 403 explicit_deny', [kiosk.status, kiosk.body?.error?.reason], [403, 'explicit_deny']);

console.log('\n== Devices and grants: create, decommission ==');
const mk = (body, token = dana5) => call('POST', '/orgs/org_acme/devices', { token, body });
const toaster = await mk({ name: 'toast-01', kind: 'toaster' });
check("kind 'toaster' -> 400 invalid_kind", [toaster.status, toaster.body?.error?.reason], [400, 'invalid_kind']);
check('duplicate name -> 409', (await mk({ name: 'lab-mac-01', kind: 'macos' })).status, 409);
check('viewer creates device -> 403', (await mk({ name: 'v-01', kind: 'linux' }, viewer5)).status, 403);
const created = await mk({ name: '  new-box-01 ', kind: 'linux' });
check('create -> 201 with permissions', [created.status, created.body?.name, typeof created.body?.permissions], [201, 'new-box-01', 'object']);

check('decommission build-server-01 -> 204', (await call('DELETE', '/orgs/org_acme/devices/dev_build_server_01', { token: dana5 })).status, 204);
check('  ...seeded live session ended, device_transferred',
  db.prepare("SELECT state, end_reason FROM sessions WHERE id = 'ses_live_build_server'").get(), { state: 'ended', end_reason: 'device_transferred' });
check('  ...soft-deleted device -> 404', (await call('GET', '/orgs/org_acme/devices/dev_build_server_01', { token: dana5 })).status, 404);

console.log('\n== Devices and grants: transfer ==');
const xfer = (id, toOrgId, token = dana5) => call('POST', `/orgs/org_acme/devices/${id}/transfer`, { token, body: { toOrgId } });
check('to a non-member org -> 404', (await xfer('dev_qa_android_01', 'org_nope')).status, 404);
check('to an org without provision (Globex viewer) -> 403', (await xfer('dev_qa_android_01', 'org_globex')).status, 403);
const newOrg = (await call('POST', '/orgs', { token: dana5, body: { name: 'Transfer Target' } })).body;
const qaGrant = await call('POST', '/orgs/org_acme/grants', { token: dana5,
  body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:control'], deviceId: 'dev_qa_android_01' } });
check('setup: device-scoped grant on qa-android-01', qaGrant.status, 201);
db.prepare(`INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
            VALUES ('ses_qa_live', 'org_acme', 'usr_acme_viewer', 'dev_qa_android_01', 'view', 'active', '{}', ?)`)
  .run(new Date(Date.now() + 36e5).toISOString());
const moved = await xfer('dev_qa_android_01', newOrg.id);
check('transfer -> 200', [moved.status, moved.body], [200, { id: 'dev_qa_android_01', orgId: newOrg.id }]);
check('  ...404 in the source org', (await call('GET', '/orgs/org_acme/devices/dev_qa_android_01', { token: dana5 })).status, 404);
const newOrgTok = (await call('POST', '/auth/token', { token: dana5, body: { orgId: newOrg.id } })).body.token;
check('  ...listed in the target org',
  (await call('GET', `/orgs/${newOrg.id}/devices`, { token: newOrgTok })).body.devices.some((d) => d.id === 'dev_qa_android_01'), true);
check('  ...its session ended',
  db.prepare("SELECT state, end_reason FROM sessions WHERE id = 'ses_qa_live'").get(), { state: 'ended', end_reason: 'device_transferred' });
check('  ...its source grant revoked',
  db.prepare('SELECT revoked_at IS NOT NULL AS r FROM grants WHERE id = ?').get(qaGrant.body.id).r, 1);

console.log('\n== Devices and grants: grant validation ==');
const grant = (body, token = dana5) => call('POST', '/orgs/org_acme/grants', { token, body });
const base = { userId: 'usr_acme_viewer', effect: 'allow' };
const teleport = await grant({ ...base, permissions: ['device:teleport'] });
check('device:teleport -> 400 unknown_permission', [teleport.status, teleport.body?.error?.reason], [400, 'unknown_permission']);
check("'Device:Control' -> 400", (await grant({ ...base, permissions: ['Device:Control'] })).status, 400);
check('[] -> 400', (await grant({ ...base, permissions: [] })).status, 400);
const expired = await grant({ ...base, permissions: ['device:view'], expiresAt: new Date(Date.now() - 1000).toISOString() });
check('expired expiresAt -> 400 GRANT_EXPIRED', [expired.status, expired.body?.error?.code], [400, 'GRANT_EXPIRED']);
const offsetTs = new Date(Date.now() + 864e5).toISOString().replace('Z', '+00:00');
const offset = await grant({ ...base, permissions: ['device:view'], deviceId: 'dev_lab_win_01', expiresAt: offsetTs });
check("'+00:00' expiresAt accepted, stored with Z",
  [offset.status, db.prepare('SELECT expires_at FROM grants WHERE id = ?').get(offset.body?.id)?.expires_at.endsWith('Z')], [201, true]);
check('self-grant -> 403', (await grant({ ...base, userId: 'usr_dana', permissions: ['audit:read'] })).status, 403);
check('cross-org deviceId -> 404', (await grant({ ...base, permissions: ['device:view'], deviceId: 'dev_globex_desk_01' })).status, 404);
const scoped = await grant({ ...base, permissions: ['org:delete'], deviceId: 'dev_lab_win_01' });
check('device-scoped org:delete -> 400 scope_mismatch', [scoped.status, scoped.body?.error?.reason], [400, 'scope_mismatch']);
const admin5 = await tokOf('admin@acme.test');
check('admin denies an owner -> 403',
  (await grant({ userId: 'usr_acme_owner', effect: 'deny', permissions: ['device:view'] }, admin5)).status, 403);

console.log('\n== Devices and grants: laundering ==');
check('setup: owner denies admin device:terminal org-wide',
  (await grant({ userId: 'usr_acme_admin', effect: 'deny', permissions: ['device:terminal'] })).status, 201);
const adminFresh = await tokOf('admin@acme.test');
check('admin grants device:terminal to an operator -> 403',
  (await grant({ userId: 'usr_sam', effect: 'allow', permissions: ['device:terminal'] }, adminFresh)).status, 403);
check('setup: Sam gets org-wide grant:create',
  (await grant({ userId: 'usr_sam', effect: 'allow', permissions: ['grant:create'] })).status, 201);
check('setup: Sam gets device:provision on lab-mac-01',
  (await grant({ userId: 'usr_sam', effect: 'allow', permissions: ['device:provision'], deviceId: 'dev_lab_mac_01' })).status, 201);
const samFresh = await tokOf('sam@example.test');
check('Sam grants device:provision ORG-WIDE -> 403',
  (await grant({ userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:provision'] }, samFresh)).status, 403);
check('  ...the same grant scoped to lab-mac-01 -> 201',
  (await grant({ userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:provision'], deviceId: 'dev_lab_mac_01' }, samFresh)).status, 201);

console.log('\n== Devices and grants: revoke ==');
const revoke = (id, token = dana5) => call('DELETE', `/orgs/org_acme/grants/${id}`, { token });
check('revoke -> 204', (await revoke(offset.body.id)).status, 204);
check('already revoked -> 404', (await revoke(offset.body.id)).status, 404);
const ownerTok = await tokOf('owner@acme.test');
const onDana = await grant({ userId: 'usr_dana', effect: 'deny', permissions: ['device:terminal'] }, ownerTok);
check('setup: another owner puts a grant on dana', onDana.status, 201);
check('revoke a grant on yourself -> 403', (await revoke(onDana.body.id, await tokOf('dana@example.test'))).status, 403);
const samGrants = (await call('GET', '/orgs/org_acme/grants?userId=usr_sam', { token: ownerTok })).body.grants;
check('GET grants?userId filters, rows carry status',
  samGrants.length > 0 && samGrants.every((g) => g.userId === 'usr_sam' && g.status === 'active'), true);

console.log('\n== Devices and grants: device list query count does not grow ==');
{
  // In-process, so every statement the handler runs can be counted.
  let n = 0;
  const counted = new Proxy(db, { get(t, k) {
    if (k === 'prepare') return (sql) => { const st = t.prepare(sql);
      return new Proxy(st, { get(s, m) { const v = s[m];
        return ['get', 'all', 'run'].includes(m) ? (...a) => (n++, v.apply(s, a)) : typeof v === 'function' ? v.bind(s) : v; } }); };
    const v = t[k]; return typeof v === 'function' ? v.bind(t) : v; } });
  const router = createRouter();
  registerRoutes(router, { db: counted, secret: SECRET });
  const listOnce = async () => {
    const hit = router.match('GET', `/v1/orgs/${newOrg.id}/devices`);
    const ctx = { db: counted, requestId: 'req_count', query: new URLSearchParams(), body: {}, req: {} };
    Object.assign(ctx, authenticate(db, SECRET)({ headers: { authorization: `Bearer ${newOrgTok}` } }, hit.params));
    let body;
    const res = { setHeader() {}, writeHead() {}, end(b) { body = JSON.parse(b); } };
    n = 0;
    await hit.handler(ctx, hit.params, res);
    return { n, rows: body.devices.length };
  };
  // The transfer-target org already holds qa-android-01; dana owns it.
  const addDevice = (i) => db.prepare("INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, 'linux')")
    .run(`dev_cnt_${i}`, newOrg.id, `cnt-${i}`);
  addDevice(1);
  const two = await listOnce();
  addDevice(2); addDevice(3); addDevice(4);
  const five = await listOnce();
  console.log(`   statements: ${two.n} for ${two.rows} devices, ${five.n} for ${five.rows} devices`);
  check('same statement count for 2 and 5 devices', [two.rows, five.rows, five.n === two.n], [2, 5, true]);
}

// ===========================================================================
// Sessions, audit completion, engine fixes. Fresh fixture again.
await restart(8126);
console.log('\n== Sessions: session start, the compound check ==');
const dana6 = await tokOf('dana@example.test');
let viewer6 = await tokOf('viewer@acme.test');
const sam6 = await tokOf('sam@example.test');
const start = (token, deviceId, mode) => call('POST', '/orgs/org_acme/sessions', { token, body: { deviceId, mode } });
const sView = await start(viewer6, 'dev_lab_mac_01', 'view');
check('viewer: view on lab-mac-01 -> 201', sView.status, 201);
const qa = await start(viewer6, 'dev_qa_android_01', 'view');
check('viewer: view on qa-android-01 -> 403 missing_permission', [qa.status, qa.body?.error?.reason], [403, 'missing_permission']);
const ctl = await start(viewer6, 'dev_lab_mac_01', 'control');
check('viewer: control on lab-mac-01 -> 403 missing_device_permission', [ctl.status, ctl.body?.error?.reason], [403, 'missing_device_permission']);
check("mode 'shell' -> 400", (await start(viewer6, 'dev_lab_mac_01', 'shell')).status, 400);
check('device in another org -> 404', (await start(dana6, 'dev_globex_desk_01', 'view')).status, 404);

console.log('\n== Sessions: exclusivity ==');
const held1 = await start(sam6, 'dev_lab_win_01', 'control');
check('control -> 201', held1.status, 201);
const busy = await start(dana6, 'dev_lab_win_01', 'control');
check('2nd control -> 409 DEVICE_BUSY naming the holder',
  [busy.status, busy.body?.error?.code, busy.body?.error?.message.includes(held1.body.id)], [409, 'DEVICE_BUSY', true]);
check('view alongside -> 201', (await start(dana6, 'dev_lab_win_01', 'view')).status, 201);
check('terminal while control is held -> 409', (await start(dana6, 'dev_lab_win_01', 'terminal')).status, 409);
const pair = await Promise.all([1, 2].map(() => start(dana6, 'dev_qa_android_01', 'control')));
check('two control starts in parallel -> one 201, one 409', pair.map((x) => x.status).sort(), [201, 409]);

console.log('\n== Sessions: expiry releases the device ==');
db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), held1.body.id);
const after = await start(dana6, 'dev_lab_win_01', 'control');
check('expired holder: new control -> 201', after.status, 201);
check('  ...old one ended, session_expired',
  db.prepare('SELECT state, end_reason FROM sessions WHERE id = ?').get(held1.body.id), { state: 'ended', end_reason: 'session_expired' });

console.log('\n== Sessions: authority snapshot and grandfathering ==');
check("viewer's session snapshot names the grant", sView.body.authorized_by.grantIds, ['grt_viewer_start_session']);
const ownerSnap = pair.find((x) => x.status === 201).body.authorized_by;
check("owner's snapshot: role owner, no grants", [ownerSnap.role, ownerSnap.grantIds], ['owner', []]);
check('revoke the grant -> 204', (await call('DELETE', '/orgs/org_acme/grants/grt_viewer_start_session', { token: dana6 })).status, 204);
check('  ...the running session stays active',
  db.prepare('SELECT state FROM sessions WHERE id = ?').get(sView.body.id).state, 'active');
viewer6 = await tokOf('viewer@acme.test');
check('  ...the next start -> 403', (await start(viewer6, 'dev_lab_mac_01', 'view')).status, 403);

console.log('\n== Sessions: org TTL ==');
check('PATCH maxSessionMinutes 5 -> 200',
  (await call('PATCH', '/orgs/org_acme', { token: dana6, body: { maxSessionMinutes: 5 } })).status, 200);
const short = (await start(dana6, 'dev_lab_mac_01', 'view')).body;
const ttl = (Date.parse(short.expires_at) - Date.parse(short.started_at)) / 1000;
check('  ...new session expires started_at + 5 min', Math.abs(ttl - 300) <= 2, true);

console.log('\n== Sessions: GET /sessions/:id ==');
check('participant reads own session -> 200', (await call('GET', `/sessions/${sView.body.id}`, { token: viewer6 })).status, 200);
check('setup: org-wide deny session:view on Sam',
  (await call('POST', '/orgs/org_acme/grants', { token: dana6, body: { userId: 'usr_sam', effect: 'deny', permissions: ['session:view'] } })).status, 201);
const samNow = await tokOf('sam@example.test');
check("Sam reads someone else's session -> 403", (await call('GET', `/sessions/${short.id}`, { token: samNow })).status, 403);
db.prepare(`INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
            VALUES ('ses_gx_other', 'org_globex', 'usr_globex_owner', 'dev_globex_desk_01', 'view', 'active', '{}', ?)`)
  .run(new Date(Date.now() + 36e5).toISOString());
check('a session id from another org -> 404', (await call('GET', '/sessions/ses_gx_other', { token: dana6 })).status, 404);

console.log('\n== Sessions: DELETE /sessions/:id ==');
const stop = (id, token) => call('DELETE', `/sessions/${id}`, { token });
const own = await stop(sView.body.id, viewer6);
check('own -> 200 user_stopped', [own.status, own.body?.end_reason], [200, 'user_stopped']);
check("someone else's without session:terminate -> 403", (await stop(short.id, samNow)).status, 403);
const byAdmin = await stop(short.id, await tokOf('admin@acme.test'));
check('admin -> 200 admin_terminated', [byAdmin.status, byAdmin.body?.end_reason], [200, 'admin_terminated']);
check('again -> 409', (await stop(short.id, dana6)).status, 409);

console.log('\n== Sessions: a suspended member is refused, and it is audited ==');
check('suspend sam -> 200', (await call('POST', '/orgs/org_acme/members/usr_sam/suspend', { token: dana6 })).status, 200);
// A token minted after the suspension (current pv), so freshness passes and suspension decides.
const { perm_version: samPv } = db.prepare("SELECT perm_version FROM memberships WHERE org_id = 'org_acme' AND user_id = 'usr_sam'").get();
const samSuspended = issueAccessToken({ userId: 'usr_sam', orgId: 'org_acme', role: 'operator', permVersion: samPv }, SECRET);
const refused = await call('GET', '/orgs/org_acme/devices', { token: samSuspended });
check('suspended, fresh token -> 403 suspended', [refused.status, refused.body?.error?.reason], [403, 'suspended']);
const deny = db.prepare(
  "SELECT action, reason_code FROM audit_events WHERE org_id = 'org_acme' AND actor_id = 'usr_sam' AND result = 'deny' AND reason_code = 'suspended'").get();
check('  ...audit has the deny row', deny, { action: 'GET /v1/orgs/org_acme/devices', reason_code: 'suspended' });

console.log('\n== Sessions fix 1: a device-scoped org:delete row does not lift ==');
db.prepare(`INSERT INTO grants (id, org_id, user_id, device_id, effect, created_by)
            VALUES ('grt_bad_scope', 'org_acme', 'usr_acme_admin', 'dev_lab_mac_01', 'allow', 'usr_dana')`).run();
db.prepare("INSERT INTO grant_permissions (grant_id, permission) VALUES ('grt_bad_scope', 'org:delete')").run();
const eff = await call('GET', '/orgs/org_acme/users/usr_acme_admin/effective', { token: dana6 });
check("admin's org-level org:delete stays deny", eff.body?.permissions?.['org:delete']?.effect, 'deny');

console.log('\n== Sessions fix 2: transfer target needs provision org-wide ==');
const gxOwner = await tokOf('owner@globex.test');
check('setup: dana gets device:provision on one Globex device',
  (await call('POST', '/orgs/org_globex/grants', { token: gxOwner,
    body: { userId: 'usr_dana', effect: 'allow', permissions: ['device:provision'], deviceId: 'dev_globex_desk_01' } })).status, 201);
check('transfer into Globex -> 403',
  (await call('POST', '/orgs/org_acme/devices/dev_lab_mac_01/transfer', { token: dana6, body: { toOrgId: 'org_globex' } })).status, 403);

// ===========================================================================
// Hardening. Fresh fixture.
await restart(8127);
const dana8 = await tokOf('dana@example.test');
const gxOwner8 = await tokOf('owner@globex.test');
// Real ids, so it is the permission (or the org) that refuses, never a missing row.
const acmeInvite = (await call('POST', '/orgs/org_acme/invites', { token: dana8, body: { email: 'hardening@example.test', role: 'viewer' } })).body.id;
const gxInvite = (await call('POST', '/orgs/org_globex/invites', { token: gxOwner8, body: { email: 'hardening@example.test', role: 'viewer' } })).body.id;
db.prepare(`INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
            VALUES ('ses_gx_m8', 'org_globex', 'usr_globex_owner', 'dev_globex_desk_01', 'view', 'active', '{}', ?)`)
  .run(new Date(Date.now() + 36e5).toISOString());

console.log('\n== Hardening: hidden elements are refused by the API (viewer) ==');
{
  const viewer8 = await tokOf('viewer@acme.test');
  const A = '/orgs/org_acme';
  const table = [
    ['POST', `${A}/devices`, { name: 'v-02', kind: 'linux' }],
    ['PATCH', `${A}/devices/dev_lab_mac_01`, { name: 'renamed' }],
    ['DELETE', `${A}/devices/dev_lab_mac_01`],
    ['POST', `${A}/devices/dev_lab_mac_01/transfer`, { toOrgId: 'org_globex' }],
    ['POST', `${A}/grants`, { userId: 'usr_sam', effect: 'allow', permissions: ['device:view'] }],
    ['DELETE', `${A}/grants/grt_sam_deny_terminal_orgwide`],
    ['POST', `${A}/invites`, { email: 'v@example.test', role: 'viewer' }],
    ['GET', `${A}/invites`],
    ['DELETE', `${A}/invites/${acmeInvite}`],
    ['PATCH', `${A}/members/usr_sam`, { role: 'viewer' }],
    ['POST', `${A}/members/usr_sam/suspend`],
    ['DELETE', `${A}/members/usr_sam/suspend`],
    ['DELETE', `${A}/members/usr_sam`],
    ['PATCH', A, { name: 'Pwned' }],
    ['DELETE', A],
    ['GET', `${A}/audit`],
    ['POST', `${A}/sessions`, { deviceId: 'dev_lab_mac_01', mode: 'control' }],
  ];
  for (const [method, path, body] of table) {
    const r = await call(method, path, { token: viewer8, body });
    check(`${method} ${path.replace(A, '')} -> 403 with reason`, [r.status, typeof r.body?.error?.reason], [403, 'string']);
  }
}

console.log('\n== Hardening: cross-org is 404 everywhere ==');
{
  // Every org-scoped route the router knows, so a new route is covered without editing this table.
  const router = createRouter();
  registerRoutes(router, { db, secret: SECRET });
  const ids = { devices: 'dev_globex_desk_01', grants: 'grt_dana_control_one_device', invites: gxInvite,
    members: 'usr_globex_owner', users: 'usr_globex_owner' };
  const nope = withoutRequestId((await call('GET', '/orgs/org_nope/devices', { token: dana8 })).body);
  const orgRoutes = router.routes.filter((r) => r.segments[2] === ':org');
  for (const { method, segments } of orgRoutes) {
    const path = '/' + segments.slice(1).map((s, i, a) =>
      s === ':org' ? 'org_globex' : s.startsWith(':') ? ids[a[i - 1]] : s).join('/');
    const r = await call(method, path, { token: dana8, body: method === 'GET' || method === 'DELETE' ? undefined : {} });
    check(`${method} ${path} -> 404, same body`, [r.status, withoutRequestId(r.body)], [404, nope]);
  }
  check(`  ...the table is the router's (${orgRoutes.length} org-scoped routes)`, orgRoutes.length >= 24, true);

  const A = '/orgs/org_acme';
  const byId = [
    ['GET', `${A}/devices/dev_globex_desk_01`],
    ['PATCH', `${A}/devices/dev_globex_desk_01`, { name: 'x' }],
    ['DELETE', `${A}/devices/dev_globex_desk_01`],
    ['POST', `${A}/devices/dev_globex_desk_01/transfer`, { toOrgId: 'org_globex' }],
    ['DELETE', `${A}/grants/grt_dana_control_one_device`],
    ['DELETE', `${A}/invites/${gxInvite}`],
    ['PATCH', `${A}/members/usr_globex_owner`, { role: 'viewer' }],
    ['POST', `${A}/members/usr_globex_owner/suspend`],
    ['DELETE', `${A}/members/usr_globex_owner/suspend`],
    ['DELETE', `${A}/members/usr_globex_owner`],
    ['GET', `${A}/users/usr_globex_owner/effective`],
    ['GET', '/sessions/ses_gx_m8'],
    ['DELETE', '/sessions/ses_gx_m8'],
  ];
  for (const [method, path, body] of byId) {
    const r = await call(method, path, { token: dana8, body });
    check(`Globex id: ${method} ${path.replace(A, '')} -> 404`, [r.status, withoutRequestId(r.body)], [404, nope]);
  }
}

console.log('\n== Hardening: token edge cases ==');
{
  const claims = JSON.parse(Buffer.from(dana8.split('.')[1], 'base64url').toString());
  const forge = (c) => signToken(c, SECRET);
  const me = async (token) => (await call('GET', '/auth/me', { token })).status;
  check('control: re-signed real claims -> 200', await me(forge(claims)), 200);
  for (const [label, token] of [
    ['payload null', forge(null)],
    ['payload []', forge([])],
    ['payload "x"', forge('x')],
    ['aud ["remoteops-api"]', forge({ ...claims, aud: ['remoteops-api'] })],
    ['jti 123', forge({ ...claims, jti: 123 })],
    ['exp true', forge({ ...claims, exp: true })],
    ['expired exp', forge({ ...claims, exp: Math.floor(Date.now() / 1000) - 1 })],
  ]) check(`${label} -> 401`, await me(token), 401);

  const d = await login('dana@example.test');
  check('refresh token as Bearer -> 401', await me(cookieOf(d).slice('rt='.length)), 401);

  check('setup: remove admin', (await call('DELETE', '/orgs/org_acme/members/usr_acme_admin', { token: dana8 })).status, 204);
  const { perm_version: pv } = db.prepare("SELECT perm_version FROM memberships WHERE org_id = 'org_acme' AND user_id = 'usr_acme_admin'").get();
  const removed = issueAccessToken({ userId: 'usr_acme_admin', orgId: 'org_acme', role: 'admin', permVersion: pv }, SECRET);
  check('token for a REMOVED membership (current pv) -> 401', await me(removed), 401);
}

console.log('\n== Hardening: malformed input ==');
{
  const raw = async (method, path, body) => {
    try {
      const res = await fetch(BASE + path, { method, body,
        headers: { authorization: `Bearer ${dana8}`, 'content-type': 'application/json' } });
      return res.status;
    } catch (err) {
      return `network error: ${err.cause?.code ?? err.message}`;
    }
  };
  const P = '/orgs/org_acme/devices/dev_lab_mac_01';
  check('body is an array -> 400', await raw('PATCH', P, '[{"name":"x"}]'), 400);
  check('invalid JSON -> 400', await raw('PATCH', P, '{"name":'), 400);
  check('1.1 MB body -> 400', await raw('PATCH', P, JSON.stringify({ name: 'x'.repeat(1_100_000) })), 400);
  check('  ...and the server still answers', await raw('PATCH', P, '{"name":"lab-mac-01"}'), 200);
  check('PATCH device {name: 123} -> 400', (await call('PATCH', P, { token: dana8, body: { name: 123 } })).status, 400);
  check('POST grants permissions as a string -> 400',
    (await call('POST', '/orgs/org_acme/grants', { token: dana8,
      body: { userId: 'usr_sam', effect: 'allow', permissions: 'device:view' } })).status, 400);
  const noDevice = (await call('POST', '/orgs/org_acme/sessions', { token: dana8, body: { mode: 'view' } })).status;
  check('POST sessions without deviceId -> 400 or 404', [400, 404].includes(noDevice), true);
}

// Give stderr a moment to drain, then scan everything the servers logged this run.
await new Promise((r) => setTimeout(r, 200));
check('server log: zero "unhandled" across the run', (serverLog.match(/unhandled/g) ?? []).length, 0);

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
db.close();
server.kill();
process.exit(fail === 0 ? 0 : 1);
