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

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
