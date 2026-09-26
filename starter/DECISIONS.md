# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Fix the shipped scripts in place, rather than work around them in my shell

**What I chose:** patched the two broken lines the hand-out ships with — `db:reset`'s `rm -f`
(`1a34541`) and `.pathname` → `fileURLToPath` in `scripts/load-db.js:11` and `server/index.js:23`
(`8a591d3`) — and changed nothing else in `scripts/` or `server/`.
**Why:** `npm run db:reset` failed with
`ENOENT ... open 'C:\C:\Users\Sukuna\Web%20Development\...\db\schema.sql'`, and that one failure
took `check-api.js` and the Playwright webServer down with it (logged under Phase 0). The
`.pathname` half isn't Windows-only: `new URL('file:///home/a b/x.sql').pathname` is
`/home/a%20b/x.sql`, so any checkout path with a space breaks on Linux too.
**What I rejected:** developing from Git Bash or WSL. That fixes `rm -f` but not the ENOENT — the
path is mangled inside Node, not by the shell — and it leaves the bug in the repo for the next
person who clones it into `~/My Projects`. I also rejected `rimraf` for the delete: a
dependency for something `fs.rmSync(f, { force: true })` does in one line.
**What would change my mind:** being told the grading harness swaps in its own copy of
`scripts/`. The fix would then be harmless but redundant, and I'd keep it only for local runs.

---

### A token's signature is compared as its canonical text, not as decoded bytes

**What I chose:** `verifyAccessToken` re-encodes the expected HMAC as base64url and compares it
with the signature segment as strings (lengths first, then `timingSafeEqual`), in
`server/auth.js` (`36dfb57`).
**Why:** a signature ending `MOk` and the same signature ending `MOl` decode to identical bytes —
the last base64url character of a 32-byte value carries 2 unused bits (logged under Phase 1).
**What I rejected:** decoding the segment and comparing bytes, which is the common way to write it.
It accepts both spellings, so one signature yields several distinct valid token strings. Anything
that ever keys on the raw token — a denylist, a log line, a replay check — would see them as
different tokens.
**What would change my mind:** an HS256 issuer that emits non-canonical base64url. We only verify
our own tokens, and `signToken` always emits the canonical form, so I don't expect one.

---

### The org-level view can be raised by a device-scoped allow, never lowered by a device-scoped deny

**What I chose:** org-level answers come from the role baseline and org-wide grants; an active
device-scoped allow on a live device with no deny there raises it; device-scoped denies are
ignored at org level. `evaluate()` in `server/permissions.js` (`8977210`).
**Why:** the org-level view gates navigation and page-level entries. Read literally, "the union
across all devices" (PERMISSIONS.md §3) is empty for an org with no devices, so a brand-new org's
owner would resolve to deny on `device:provision` and never see Add device (BUILD-LOG, Phase 2).
**What I rejected:** the literal union over existing devices, for that reason. Also "any
device-scoped deny lowers the org-level answer": a viewer with one denied kiosk would lose the
whole Devices card while four other rows are still theirs to see.
**What would change my mind:** a case where a device-scoped deny on an org's only device is
expected to hide the org-level entry. Then I'd switch to the union for non-empty orgs and keep the
baseline as the floor only for empty ones.

---

### An allow whose window has closed reports `expired_grant`, not `implicit`

**What I chose:** when no active grant or baseline allows P but an expired allow grant covers it,
the answer is `deny`, `source: grant:<id>`, `reason: expired_grant` — step 4 of `decide()` in
`server/permissions.js` (`8977210`). A grant that hasn't started yet counts as absent.
**Why:** "implicit" means nobody granted it, which is false here — someone did, and it lapsed.
PERMISSIONS.md §5 lists `expired_grant` as a reason, and the console has to explain a lock that
used to be open differently from one that never was.
**What I rejected:** reporting `implicit` for everything that isn't an explicit deny. It is simpler
and passes every shipped test (`check-permissions.js` only asserts the effect for the expired
case), but it makes "your access ran out" read as "you never had access".
**What would change my mind:** a test that pins the reason for an expired grant to `implicit`. I'd
comply and keep the provenance in `source` only.

---

### Removing a member revokes their grants in that org

**What I chose:** `removeMember` (`server/routes/orgs.js`, `41decaf`) sets `revoked_at` on the
user's unrevoked grants in the org, in the same transaction as the status change, the pv bump and
ending their sessions. Suspension leaves grants alone.
**Why:** `memberships` is `UNIQUE (org_id, user_id)`, so a re-invite has to reactivate the
removed row. Grants key on `(org_id, user_id)` too, so anything left unrevoked comes back the
moment the person is rehired (BUILD-LOG, Phase 3). `check-edges.js` asserts the grant is revoked.
**What I rejected:** leaving grants in place, which AUTH-DATA-MODEL.md §7's removal steps imply.
Resolution already ignores them while the membership is `removed`, so nothing breaks today — the
bug only appears on rehire, as authority nobody re-approved.
**What would change my mind:** a requirement that a rehire restores prior access. I'd still
revoke, and make restoring them an explicit action rather than a side effect.

---

### Suspension is reversible without touching grants; removal is not

**What I chose:** suspend flips `status` and bumps pv; reinstate flips it back. Grants,
role and history stay. Remove sets `removed` and revokes grants. Both end the user's sessions in
that org (`user_suspended` vs `membership_removed`).
**Why:** check-api suspends Sam and then reinstates her with `200`, expecting her back as she was.
Suspension is a pause; removal is the end of a tenancy.
**What I rejected:** revoking grants on suspension too, for symmetry. Reinstating would then
restore a different person from the one who was suspended.
**What would change my mind:** long suspensions being used as a soft removal in practice. Then a
suspension older than some bound should expire into a removal.

---

### Accepting an invite for an existing account requires that account's password

**What I chose:** `POST /invites/:token/accept` creates a user only when the email has none. If
it does, `body.password` must verify against the stored hash — same `401` as a bad login
otherwise — and the stored name and password are left alone (`server/routes/invites.js`,
`525cc2c`).
**Why:** accept returns an access token and sets the refresh cookie. For an existing user, that
cookie opens every org they belong to. `check-edges.js` covers both paths: wrong password `401`,
right password `200`, same user id, one `users` row.
**What I rejected:** the literal "upsert the user" of AUTH-DATA-MODEL.md §6 on the token alone.
Then an invite link sent to the wrong address, or forwarded, or leaked from a mail log, becomes a
full login as that person. The invite is proof someone may join this org, not proof of who they
are.
**What would change my mind:** invite tokens delivered only to verified mailboxes, with accept
issuing a session for the invited org only — not a refresh cookie for the whole account.

---

### A double invite is refused by the unique index, after retiring expired invites in the same transaction

**What I chose:** invite creation first sets `revoked_at` on that (org, email)'s expired, unaccepted
invite, then inserts. A live duplicate hits `one_live_invite_per_email`; `SQLITE_CONSTRAINT_UNIQUE`
maps to `409` (`525cc2c`).
**Why:** the index predicate ignores `expires_at` (BRIEF §2 and the schema agree on the columns),
so without the retire step an expired invite blocks its email permanently — logged under
Phase 3, covered by the expire-then-reinvite case in `check-edges.js`.
**What I rejected:** checking for a live invite with a `SELECT` before inserting. With the index
already there, a pre-check adds a race window and duplicates the rule. Also rejected: counting
`expires_at` myself instead of revoking — the index would still see the old row as live.
**What would change my mind:** being allowed to change the schema. Then the fix belongs in the
predicate, not in a housekeeping `UPDATE` — though SQLite's partial indexes can't reference
`now`, so it would still have to be a stored flag.

---

### An org-wide grant needs the permission held org-wide; a device-scoped one can only name device and session permissions

**What I chose:** `assertMayGrant` checks an org-wide grant against baseline + org-wide grants
only, and a device-scoped grant against the caller's answer on that device (`e64eab6`). Device-scoped
grants may only name `device`/`session` permissions or their wildcards; anything else, including
`*`, is `400 scope_mismatch` (`a8f04f6`). Rank rules apply to grant targets as well.
**Why:** both follow from my own org-level lift (DECISIONS, above). The lift is right for navigation
but wrong as a measure of what you *hold*: `check-edges.js` shows Sam holding `device:provision`
on one device and getting `403` for the org-wide version. A scratch-database check showed a
device-scoped `org:delete` lifting an admin to org-level `org:delete` (BUILD-LOG, Phase 4).
**What I rejected:** checking laundering against the normal org-level view — the obvious reuse of
`resolve()`, and exactly the hole. Also rejected: letting a device-scoped `org:delete` through as
harmless because it's "on a device"; it isn't harmless once the lift sees it.
**What would change my mind:** a permission outside `device`/`session` that genuinely varies per
device. Then `DEVICE_SCOPED_RESOURCES` becomes a column on `permissions` rather than a constant —
which would need a schema change I'm not allowed to make.

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

- **`playwright.config.js` vs `package.json`.** The config comment says "`npm test` builds the
  SPA first", but `"test": "playwright test"` has no build step. The webServer runs with
  `NODE_ENV=production`, so it serves `dist/`, which only exists after `npm run build`. I left
  both files as they are and run `npm run build` before `npx playwright test` myself.

- **The session-start reason the docs don't list.** PERMISSIONS.md §5: "`reason` is the
  machine-readable cause — `missing_permission`, `explicit_deny`, `suspended`, `expired_grant`,
  `scope_mismatch`." `check-permissions.js` and `check-api.js` both require
  `missing_device_permission` when the mode permission is what's missing. Built against the tests:
  it is the only way the two halves of the compound check stay distinguishable.

- **"No permissions anywhere."** PERMISSIONS.md §3 step 1: "A deleted or suspended user has no
  permissions anywhere." The schema has no way to delete a user (`users` has no `deleted_at`), and
  suspension is `memberships.status` — per org. AUTH-DATA-MODEL.md §7 agrees with the schema:
  suspension ends sessions "in that org". Built against the schema: suspended in Acme, still
  active in Globex.

- **Owners modifying owners.** PERMISSIONS.md §6: "modify a user of equal role (admin → admin) →
  `403`". `check-api.js`: "demoting a NON-last owner is allowed" — Dana (owner) demotes
  `usr_acme_owner` (owner) and expects `200`. Built against the test: equal rank is refused,
  except that an owner may modify another owner (`assertCanModify` in `server/lifecycle.js`).
  Without that exception, nobody could ever demote or remove an owner except the owner
  themselves.

- **What stops a double accept.** BRIEF.md §2: "`one_live_invite_per_email` makes a double invite,
  and a double accept, a database problem". AUTH-DATA-MODEL.md §6: "Two concurrent accepts of the
  same token: exactly one wins. The partial unique index `one_live_invite_per_email` makes that a
  database guarantee." The index is on `invites (org_id, email)`, and accepting never inserts an
  invite, so it cannot see an accept at all. Built against the schema: one conditional `UPDATE`
  with `changes === 1` decides the winner (`server/routes/invites.js`).

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
