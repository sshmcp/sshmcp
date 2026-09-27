# Human approval

Agent policy rules return `allow`, `confirm`, or `deny`. `risk` is metadata only; `effect` controls execution.

```yaml
approval:
  enabled: true
  ttl_seconds: 300
  storage: { type: sqlite, path: /data/approvals.db }
profiles:
  - name: production
    agent_policy:
      rules:
        - id: service-status
          match: { operation: exec, commands: ["systemctl status *"] }
          effect: allow
          risk: low
        - id: service-restart
          match: { operation: exec, commands: ["systemctl restart *"] }
          effect: confirm
          risk: medium
        - id: no-reboot
          match: { operation: exec, commands: ["reboot", "shutdown *"] }
          effect: deny
          risk: critical
        - id: nginx-write
          match: { operation: write, paths: ["/etc/nginx/**"] }
          effect: confirm
          risk: high
```

Rules run in order after capabilities and existing safety checks. With no rules, legacy exact `allowed_commands` and path behavior remains unchanged. An unmatched request in a non-empty ruleset is denied. Shell wrappers are not unwrapped; broad wrapper rules should not be used.

Restricted command globs (for example `systemctl status *`) only allow literal ASCII words: letters, digits, spaces and `/._-:=,@%+`. Quoting, escapes, expansions, control characters, redirections and compound shell commands cannot match an `allow` or `confirm` glob. Exact command entries and the explicit full-access `*` still authorize shell syntax; deny rules continue matching raw text. This prevents shell composition bypasses, but operators must also restrict each program's arguments: a command glob is not a read-only guarantee.

## Workflow

MCP returns `{"status":"confirmation_required","approval":{"id":"apr_...","profile":"production","operation":"exec","summary":"systemctl restart nginx","risk":"medium","expires_at":1780000000}}`. The agent must stop. A human then uses:

```console
sshmcp approval list
sshmcp approval show apr_...
sshmcp approval approve apr_...
```

Approval atomically claims the pending row, verifies its SHA-256 request hash, reruns policy and path safety checks, and executes the frozen request once. `approval reject` rejects it; `approval cleanup` removes terminal rows. `sshmcp --agent approval ...` is denied, and MCP exposes no approve/reject tools.

In self-hosted mode, profile creation and deletion use MCP client confirmation when `mcp.profile_management.enabled` is true. In Cloud runtime mode, the gateway creates a single-use approval that only the Human CLI can approve. The gateway validates the complete candidate configuration; deletion also rechecks profile dependencies, active sessions, and the profile fingerprint immediately before writing YAML. Profile management cannot create grants or appear in Plans.

Write approvals bind encoded content. Upload approvals also bind the current local file bytes, so a changed source is rejected. Remote file operations rerun remote real-path enforcement at execution to protect against symlink changes. List/show/MCP expose redacted metadata, never stored payload.

SQLite WAL and conditional state changes provide concurrency safety and restart persistence. For Docker use `/data/approvals.db`. The packaged systemd unit makes `/var/lib/sshmcp` writable; use `/var/lib/sshmcp/approvals.db` owned by `sshmcp`. If approval storage is disabled or unavailable, confirmation fails closed.

## Temporary grants

Approving without options remains one-shot. A human can derive a bounded grant from the pending approval's matched policy rule:

```console
sshmcp approval approve apr_xxx --for 30m
sshmcp approval approve apr_xxx --task task_nginx_fix --for 20m
sshmcp approval approve apr_xxx --task task_nginx_fix --max-uses 50
sshmcp grant list
sshmcp grant show grt_xxx
sshmcp grant revoke grt_xxx
```

Scope is always `profile + rule_id`, optionally restricted to `task_id`; there is no arbitrary grant-create or allow-all command. Every request still runs PolicyEngine and must return `confirm` from the same rule. `deny` is absolute, while `allow` does not consume a grant. Use consumption is atomic and is not refunded after a failed execution.

```yaml
approval:
  grants:
    max_ttl_seconds: 3600
    default_max_uses: 20
    high: { task: true, time: false }
    critical: { task: false, time: false }
```

## Plans

MCP agents may call `propose_plan` with a profile and ordered canonical Request objects. The stable task ID is injected by the gateway from `mcp.task_id_env`; it is not accepted as an agent-supplied tool argument. This only persists a proposal. A human reviews it with `sshmcp plan show pln_xxx`, then uses `plan approve` or `plan reject`.

An approved plan is immutable and hash-bound. Requests using its task ID must match the next exact action; each action is claimed once and successful completion advances the plan. A failure fails the plan. MCP exposes no plan approval tool.

The existing database is migrated in place with an idempotent schema version migration. Existing approvals are retained; grants and plans use tables in the same SQLite database.
