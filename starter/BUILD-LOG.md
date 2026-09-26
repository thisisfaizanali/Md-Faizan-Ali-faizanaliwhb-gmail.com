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

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
