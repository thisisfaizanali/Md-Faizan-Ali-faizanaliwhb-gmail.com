# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

### 2026-09-26 · the fork contains more than the hand-out

Expected: a starter with the given plumbing and stubs for the parts I write.
Observed: the repository root carries `q1-starter/`, `DISCOVERY-RUBRIC.md`, `HARDENING.md` and
`tools/` next to `starter/`. The root `README.md` describes itself as written for organisers,
calls `q1-starter/` the reference implementation, and marks the rubric and `tools/` as
organiser-only. `starter/` is the generated hand-out — every file I am meant to write is a stub
there.
Did: emailed Sravya on the task thread asking whether `starter/` is the intended hand-out and
whether I should delete the rest, since the rules disqualify code copied from the reference
solution. Building only from `starter/` and the four spec documents until I hear back.
Open: the write-up has to sit at the repository root, and today it is inside `starter/`. Holding
the move until they answer.

### 2026-09-26 · the starting line, on Windows

Expected: `npm install`, `npm run db:reset`, then every suite failing on the stubs.
Observed, in order:
- `npm install` on Node 24 died in `node-gyp` building `better-sqlite3`. `.nvmrc` says 22; on
  22.23.3 it took the prebuilt binary (`build/Release/better_sqlite3.node`, no `obj/`).
- `db:reset` starts with `rm -f`, which is not a command on Windows. Replaced the delete with a
  `node -e` + `fs.rmSync(..., { force: true })` one-liner (`1a34541`). Ran it twice — second run
  with the files already gone still exits 0.
- Wrong prediction: I thought `rm -f` was the only Windows problem. With the delete fixed, the
  load itself fails: `ENOENT ... open 'C:\C:\Users\Sukuna\Web%20Development\...\db\schema.sql'`.
  `scripts/load-db.js:10` builds paths with `new URL(p, import.meta.url).pathname` — on Windows
  that keeps the leading `/C:` and the `%20` from the space in my folder name. Same pattern at
  `server/index.js:22` (`DIST`). The other scripts pass the URL object straight to
  `readFileSync`, which is fine, so it is exactly those two lines.
- Because of it, `check-api.js` and Playwright die in setup, before a single assertion.

Baseline counts against the untouched stubs:
- `check-jwt.js`: 0 passed, 43 failed — the stub throws `NOT_IMPLEMENTED`.
- `check-permissions.js`: no count at all; it throws on the first `resolve()` instead of tallying.
- `npm run personalisation`: 0 / 1, "could not resolve at all".
- `check-api.js`, Playwright: blocked by the path bug above.
- Dev server boots; `GET /v1/auth/me` → `404 {"error":{"code":"NOT_FOUND",...}}` — no routes yet.

Two things to remember for later:
- Playwright's `webServer` waits on `/v1/auth/me` and does not count a `404` as ready, so the UI
  suite cannot even start until that route exists and answers `401`.
- It runs with `NODE_ENV=production`, so it serves `dist/`: `npm run build` has to come first,
  and the `index.js:22` bug would bite there too.

My fixture (`npm run fingerprint`): an extra role `reviewer` (rank 35, baseline `device:list`,
`device:view`, `user:invite`, `user:remove`) and an extra permission `device:reboot`, allowed on
one device and denied on the other in org `Ironside Labs`. Neither exists in any document — the
engine has to learn both from the tables.

### 2026-09-26 · path fix, and the suites finally fail for the right reason

Fixed both lines with `fileURLToPath(new URL(...))` (`8a591d3`). `db:reset` now loads cleanly,
twice in a row.
Checked whether this was only a Windows problem: `new URL('file:///home/a b/x.sql').pathname`
gives `/home/a%20b/x.sql` on Node, so a Linux checkout under any folder with a space breaks the
same way. It's a portability bug, not a Windows quirk.
Now the failures are real ones:
- `check-api.js`: `FAIL dana logs in — got 404 want 200`, then it aborts with
  `Cannot read properties of undefined (reading 'map')`, after 2 cases. Like
  `check-permissions.js`, it stops instead of tallying, so its count means nothing until login
  works.
- Playwright: `Timed out waiting 30000ms from config.webServer`, 0 tests run. The prediction from
  the last entry held — I booted the same server by hand (port 8124, production, `e2e.db`) and it
  came up fine; `/v1/auth/me` answering `404` is the only thing Playwright is waiting on.
- The placeholder SPA builds in 1.11s to a 224.47 kB JS bundle — the starting size, to compare
  against once the console exists.

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-26 · Buffer's base64url decoder does not reject junk

Expected: a segment with a stray character to fail decoding and fall into the `catch`.
Observed: `Buffer.from('eyJ!hIjoxfQ', 'base64url')` → `{"a":1}`. The `!` is silently dropped.
So "decode, catch errors" would have accepted a header or payload with junk in it.
Changed: `decodeObject` in `server/auth.js` tests `^[A-Za-z0-9_-]+$` before decoding.

### 2026-09-26 · two different signatures, same bytes

The last character of a 43-char base64url signature carries 2 unused bits. A signature ending
`MOk` and the same one ending `MOl` decode to identical bytes (checked with `Buffer.equals`).
Comparing decoded bytes would accept both spellings — two distinct token strings, one signature.
`verifyAccessToken` compares the canonical base64url string instead, lengths first, then
`timingSafeEqual`.

### 2026-09-26 · check-jwt.js green on the first run

`36dfb57`: 43 passed, 0 failed, first run. Header is read only to reject; signature is checked
before any claim is read. The suite can't tell those orders apart — every failure is the same
401 — and it never feeds it a non-object payload, a non-string `jti`, or an array `aud`. The
code rejects all three; nothing tests them yet. Noted for Phase 8.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-26 · "union across all devices" breaks an empty org

PERMISSIONS.md §3 defines the org-level view as the union across all devices in the org. Taken
literally, a new org has zero devices, so the union is over nothing and every permission is
deny — the owner of a fresh org would lose `device:provision` and could never add a first device.
Settled it myself: baseline + org-wide grants decide; a device-scoped allow can raise the answer,
a device-scoped deny never lowers it. `evaluate()` in `server/permissions.js` (`8977210`). No
shipped test covers either case.

### 2026-09-26 · expected 403 suspended, got 401 TOKEN_STALE

Expected a suspended member's next request to get `403 suspended` (AUTH-DATA-MODEL.md §10).
Probed `authenticate()`: with `perm_version` bumped on suspension — which `check-permissions.js`
also does — the old token gets `401 TOKEN_STALE`. Only a freshly minted token reaches the `403`.
Freshness is checked before status, so the 403 only exists after a refresh. That makes what
`/auth/refresh` does for a suspended membership the real decision, not the context check.

### 2026-09-26 · three queries, whatever the device count

Counted statements by wrapping `db.prepare`: `resolve()` = 3 (membership, catalogue + baseline,
grants), 2 for a non-member. `resolveDevices()` = 3 for 3 devices and 3 for all 7 fixture devices.
Grants are loaded once and every device is evaluated in memory.

### 2026-09-26 · a grant can outlive its device

A device-scoped grant stores `org_id` and `device_id`, but the device can be soft-deleted or
transferred to another org and the grant row doesn't change. Left alone, an allow on a device org
A no longer has would still lift A's org-level view. The grants query joins `devices` on
`id AND org_id AND deleted_at IS NULL`, so a grant only counts while its device is still there.
Untested so far — noted for Phase 8.

### 2026-09-26 · engine green on the first run

`check-permissions.js` 35/35 and `npm run personalisation` 18/18, first run (`8977210`,
`346bf5d`, `46ce35c`). Nothing public tests `resolveDevices`, the `expired_grant` reason, or
`assertCan`'s reason codes yet.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

### 2026-09-26 · the last-owner demote I planned to test can't happen

Planned an edge case: demote the last owner, expect `409 LAST_OWNER`. It is unreachable. Only an
owner may modify an owner (check-api needs that, see DECISIONS), and demoting yourself is
`SELF_ROLE_CHANGE` first. So whoever demotes an owner is a *second* owner. Same for suspend and
remove. The only path to `LAST_OWNER` is the sole owner leaving via `DELETE /members/me`.
`check-edges.js` tests it there; `assertNotLastOwner` still guards every path.

### 2026-09-26 · removal has to revoke grants, or a rehire gets them back

`memberships` is `UNIQUE (org_id, user_id)`, so re-inviting a removed person has to reuse their
old row rather than add one. Their grants in that org still point at the same user id. Without
touching them, rehiring someone would silently restore every exception they had when they left.
`removeMember` in `server/routes/orgs.js` sets `revoked_at` on their grants in that org
(`41decaf`); `check-edges.js` asserts it.

### 2026-09-26 · 404 before 401 on an unknown route

`check-api.js`: `no token -> 401` got `404`. `GET /orgs/org_acme/devices` isn't registered yet,
and `server/index.js` matches the route before it authenticates. Left it: the check passes once
the devices route exists. Side effect worth knowing: an anonymous caller can tell registered
routes (401) from unregistered ones (404).

### 2026-09-26 · a 500 found by reading, not by a test

`PATCH /members/:userId` with no `role` in the body: `assertCanModify` takes a missing `newRole`
to mean "not a role change" and skips role validation, then `UPDATE memberships SET role = ?`
binds `undefined`. Checked better-sqlite3 directly: `SQLITE_CONSTRAINT_NOTNULL` → unhandled →
`500`. `check-edges.js` (42/42) never sends a PATCH without a role. Fix and test to come.

Fixed in `cadf008`: the handler calls `assertRoleExists` before `assertCanModify`. `{}` and
`{role:'nope'}` both `400` now, and both are in `check-edges.js`.

### 2026-09-26 · an expired invite blocks its email forever

`one_live_invite_per_email` is `WHERE accepted_at IS NULL AND revoked_at IS NULL`. It says nothing
about `expires_at`, so an invite that expired unaccepted still counts as live, and every later
invite to that email would hit the index and `409`. The create handler retires that (org, email)'s
expired invite in the same transaction as the insert (`525cc2c`). `check-edges.js`: expire an
invite by hand, peek → `410`, re-invite the same email → `201`.

### 2026-09-26 · the index doesn't stop a double accept

The docs credit `one_live_invite_per_email` with making a double accept a database problem. It
can't: accepting doesn't insert into `invites`. What makes one of two accepts lose is the
conditional `UPDATE invites SET accepted_at ... WHERE accepted_at IS NULL AND ...` checked for
`changes === 1`. `check-edges.js` fires two accepts with `Promise.all` and gets one `200`, one
`409` — though with one connection the server runs them one after the other, so that test proves
the conditional update, not true simultaneity.

### 2026-09-26 · an invite link is not a login for an existing account

"Upsert the user" on accept, read literally, means whoever holds an invite for an existing email
is signed in as that person — in every org they belong to, not just this one. Accept now requires
that account's password; a wrong one gets the same `401` body as a bad login, and the name and
password on file are never overwritten. `check-edges.js`: wrong password `401`, right password
`200` with the same user id and still one `users` row.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-26 · my own org-level rule opened a laundering hole

The Phase 2 lift means a permission held on one device reads as `allow` at org level. A
laundering check against that view would let someone with `device:provision` on lab-mac-01 grant
`device:provision` org-wide. So `assertMayGrant` checks an org-wide grant against baseline +
org-wide grants only, no lift (`evaluateOrgWide`, `e64eab6`). `check-edges.js`: Sam, holding it on
lab-mac-01 only, grants it org-wide → `403`; the same grant scoped to lab-mac-01 → `201`.

### 2026-09-26 · a device-scoped `org:delete` turns an admin into someone who can delete the org

`org:delete` is a valid pattern, so the foreign key accepts it with a `device_id`. Checked it
against the engine on a scratch database: admin's org-level `org:delete` goes from `deny` to
`{"effect":"allow","source":"grant:g"}` once that grant exists. The API now refuses device-scoped
grants outside the `device` and `session` resources with `400 scope_mismatch` (`a8f04f6`). A row
written any other way would still lift — the engine needs the same limit.

### 2026-09-26 · two refusals I didn't write

`device:teleport` → `400 unknown_permission` and `kind: 'toaster'` → `400 invalid_kind`, with no
lookup in code for either. The first is the foreign key on `grant_permissions` →
`permission_patterns`; the second is the `CHECK (kind IN ...)` on `devices`. The handlers only map
`SQLITE_CONSTRAINT_FOREIGNKEY` / `SQLITE_CONSTRAINT_CHECK` to a 400. Both only work because
`server/db.js` turns `foreign_keys` on for every connection.

### 2026-09-26 · device list: 7 statements for 2 devices, 7 for 5

Counted in-process through a wrapped `db`: 3 for the `device:list` check, 1 for the device rows,
3 for one `resolveDevices` call covering every row. Same number at 2 and 5 devices.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

### 2026-09-27 · an expired control session still holds the device

`one_exclusive_session_per_device` is `WHERE state = 'active' AND mode IN ('control','terminal')`.
Nothing ends a session when its `expires_at` passes, so an expired control session would keep the
device `DEVICE_BUSY` forever — the same shape as the invite index. `sweepExpired` ends it with
`session_expired` inside the same transaction as the next insert, and before every session read
(`03e9fd4`, `4f55876`). `check-edges.js`: backdate a held session's expiry, start control → `201`,
and the old one reads `ended` / `session_expired`.

### 2026-09-27 · order of the compound check

`session:start` first, then the mode permission, both on the same device. The first missing one
decides the reason: `missing_permission` or `missing_device_permission`. Checking the mode
permission first would report `missing_device_permission` for a viewer on qa-android-01, who
lacks both — true, but it hides that they can't open sessions there at all. `check-api.js` §9
pins it: qa-android-01 → `missing_permission`, lab-mac-01 control → `missing_device_permission`.

### 2026-09-27 · the race is a unique index, not a check

`POST /sessions` never looks for an existing holder before inserting. It inserts and maps
`SQLITE_CONSTRAINT_UNIQUE` to `409 DEVICE_BUSY`, then looks up the holder for the message.
`check-edges.js` fires two control starts with `Promise.all`: one `201`, one `409`. First full
`check-api.js` run: 66/66.

### 2026-09-27 · proved the engine fix against the old code

Re-ran the scratch-database probe from Phase 4 on `6ed9886`. Same data — admin with a device-scoped
`org:delete` grant. Before: org-level `{"effect":"allow","source":"grant:g"}`. After:
`{"effect":"deny","source":null,"reason":"implicit"}`. On that one device it still resolves
`allow`, which is inert: every route checks `org:delete` at org level.

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

### 2026-09-27 · the one denial the wrapper couldn't see

Every handler is wrapped once so a `403` is written as a deny row (`41decaf`). A suspended member
is refused in `authenticate()`, before any handler runs, so those refusals never reached the
wrapper — a suspended person could probe every route and leave no trace. `context.js` now writes
that row itself (`03e9fd4`), with `request_id` null because `authenticate()` is never given it.
`check-edges.js`: suspend, fresh token, any request → `403`, and a deny row with `suspended`.

### 2026-09-27 · where I drew the line

Audited: every successful mutation (one row, in the same transaction as the write) and every
`403`, with the engine's reason. Not audited: `404`s — writing "someone probed org B" into org B's
log would tell B's auditors about a user who isn't theirs — and `409 DEVICE_BUSY`, which is a
conflict over a device, not a refusal of authority. Reads aren't audited either.

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
