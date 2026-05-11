# Configuration

Barbican has zero config files. Everything is an environment variable you set before Claude Code launches.

Every `BARBICAN_*` variable lowers or raises a specific safety check. None enable new attack shapes; they relax denies. An attacker who can write to your shell startup (`.zshrc`, `.bashrc`, `.envrc`, IDE-managed env files) can set these; see [Security model § Untrusted launch environment](./security.md#untrusted-launch-environment).

## Deny-relaxing knobs

| Variable | Default | What it does |
|---|---|---|
| `BARBICAN_SAFE_READ_ALLOW_SENSITIVE` | unset | Any nonzero/truthy value turns the sensitive-path denylist in `safe_read` off entirely. Read-once escape hatch; leave unset in normal operation. |
| `BARBICAN_SAFE_READ_ALLOW` | unset | Colon-separated absolute paths that are narrowly allowed even if they match the sensitive-path denylist. Each entry must be an absolute path and is verified to not itself be a symlink. |
| `BARBICAN_GIT_HARD_DENY` | `1` | Set to `0` to downgrade the `m2_git_hard_deny` classifier from a deny to an allow. Covers `git -c credential.helper=` injection, `git push` to attacker-controlled URLs, etc. |
| `BARBICAN_ALLOW_IP_LITERALS` | unset | Any nonzero/truthy value lets `safe_fetch` accept URLs with raw IP literals (`http://1.2.3.4/`). Default denies — SSRF's favorite evasion is "hostname is an IP literal, no DNS rebinding needed." |
| `BARBICAN_ALLOW_MALFORMED_HOOK_JSON` | unset | Any nonzero/truthy value makes the hook exit `0 (allow)` instead of `2 (deny)` when Claude Code sends it non-UTF-8 or unparseable JSON on stdin. Default denies; the relaxed mode exists because the pre-1.3.7 hook would crash. |

## Interpreter selection (for wrapper binaries)

Each `barbican-LANG` wrapper binary gates the underlying interpreter at a fixed absolute path. You can override it via the corresponding env var; the value must be an absolute path (no `..` traversal).

| Variable | Default interpreter |
|---|---|
| `BARBICAN_SHELL` | `bash` (via `PATH`) |
| `BARBICAN_PYTHON` | `python3` |
| `BARBICAN_NODE` | `node` |
| `BARBICAN_RUBY` | `ruby` |
| `BARBICAN_PERL` | `perl` |

Barbican intentionally does **not** read `$SHELL` for the shell wrapper — that would make the attack surface of the wrapper depend on the caller's environment, which is exactly what the wrapper is meant to gate.

## Resource limits

| Variable | Default | What it does |
|---|---|---|
| `BARBICAN_SAFE_FETCH_MAX_BYTES` | `5 * 1024 * 1024` (5 MiB) | Response-body cap for `safe_fetch`. Bodies over the cap truncate; the truncation is logged into the MCP response. |
| `BARBICAN_SAFE_FETCH_TIMEOUT_SECS` | `30` | Per-request timeout. Applies to each redirect hop. |
| `BARBICAN_SAFE_READ_MAX_BYTES` | `5 * 1024 * 1024` (5 MiB) | Read cap for `safe_read`. |
| `BARBICAN_SAFE_READ_EXTRA_DENY` | unset | Colon-separated extra absolute paths to add to the sensitive-path denylist. |
| `BARBICAN_SCAN_MAX_BYTES` | `5 * 1024 * 1024` (5 MiB) | Cap for the prompt-injection scanner. A sub-4 KiB value is silently raised to the 4 KiB floor so an attacker-influenced env can't effectively disable scanning. |

## Logging

| Variable | Default | What it does |
|---|---|---|
| `BARBICAN_LOG` | `warn` | `tracing`-style filter (`off`, `error`, `warn`, `info`, `debug`, `trace`). Default surfaces denials and misconfiguration warnings but stays out of the session terminal noise. |

## Audit log

Audit entries always land in `~/.claude/barbican/audit.log` at mode `0o600`. Not configurable. One JSONL line per decision, ANSI-stripped and truncated to 4000 bytes per string field.

See `docs/SECURITY.md § Audit log` in the source tree for the schema.
