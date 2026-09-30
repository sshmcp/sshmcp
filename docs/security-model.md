# Security model (v0.2.0)

## Trust boundaries

MCP Bearer authentication maps to one local caller identity. OAuth JWT authentication validates signature, issuer, audience routing and required scopes, then uses `sub` as the caller subject. `mcp.tenants[].tenant_id` may provide a stable tenant identifier separate from the audience. Session namespaces hash caller type, tenant, resource, subject and client ID. CLI human and agent callers use distinct local identities.

The gateway keeps SSH credentials server side. MCP profile responses expose metadata, not passwords or passphrases. Audit command text passes through the configured secret redactor before reaching the audit sink. Private key blocks are redacted from command output. Audit events contain principal identity fields but no token field.

## Host keys and destinations

Each direct SSH hop checks the server key against its `host_key_sha256` pin when present. `runtime.host_key_mode: strict` requires a pin for every hop and rejects unknown or changed keys. `runtime.host_key_mode: insecure_compatibility` accepts an unpinned key to preserve old self-hosted configurations; it is insecure against server impersonation. A configured pin is still enforced in compatibility mode. Cloud mode requires strict host keys.

Direct SSH resolves DNS once, checks every returned address, and connects to one checked IP. Cloud target policy rejects loopback, link-local, private and several reserved address ranges. A bastion resolves later hops remotely, so Cloud mode requires literal IP addresses for those hops. Cloud mode rejects delegated `via_profile` routes because this core cannot verify their ultimate destination. Self-hosted mode permits local and private destinations. Cloud mode also rejects SSH tunnel operations.

`private_worker` is a separate Cloud-assigned runtime mode. It preserves strict host-key pinning and Agent Policy, keeps SSH tunnels disabled, and permits the Worker to resolve and connect to the server from its own private network. It does not expose a general Worker-host shell, scanner, file-transfer API, or TCP proxy. The Cloud control plane supplies the authorized server record and temporary job credential; callers cannot add a different host or private key to a Worker request.

The Worker identity and SQLite execution journal are stored in its dedicated data directory with owner-only file permissions on Unix. The journal records entry before Core starts and prevents the same `execution_id` from starting twice across duplicate delivery or process restart. A lost result is reported as unknown rather than replayed. Revocation prevents new connections and jobs but cannot retract an SSH operation that already received a start grant.

## Authorization

Agent and MCP callers cannot approve their own requests. Policy deny is checked before grants and plans. SQLite approval claims transition atomically from pending to executing and cannot be replayed. Request hashes bind approval to the stored operation. Approval, grant and plan records carry an internal authorization namespace. Agent/MCP grant and plan consumption is scoped to that namespace. A human CLI administrator can inspect and approve records across namespaces; approved execution uses the requester's namespace.

## Current limitations

The compatibility host key mode remains the default for existing self-hosted YAML. Operators should configure pins and strict mode for stronger protection. Remote bastion DNS is unavailable to the gateway, so Cloud mode requires IP literals for downstream hops. Human CLI administration is currently global for records in its configured SQLite database; a hosted control plane needs its own tenant-aware administrative authorization. Cloud mode is a core safety boundary, not a production SaaS deployment profile.
