# Sovereign Node

Sovereign Node is a local, unprivileged Rust daemon that executes narrowly authorized
capabilities on a computer or server its owner controls. It is the machine-side enforcement
boundary between a Personal AI Platform's Action Broker and local resources.

```text
Personal AI Platform
        | exact owner authorization
        v
Action Broker
        | signed request over authenticated TLS
        v
Sovereign Node
        | local trust, scope, expiry, replay, and policy checks
        v
Typed local capability -> bounded result + audit receipt

Agent Green monitors security independently; Sovereign Node cannot control it.
```

This repository contains no LLM, autonomous planner, unrestricted shell, arbitrary code-upload
path, Internet-facing unauthenticated endpoint, or automatic updater. An IP address never grants
trust.

## Security posture

- Stable random `NodeId` and Ed25519 device identity created locally.
- Explicit multi-step pairing with local owner approval, proof of both owner and broker keys,
  certificate pinning, expiry, a node-signed trust receipt, revocation, and durable audit records.
- Pairing and credential rotation validate the submitted X.509 leaf and intermediates against the
  submitted CA at both request and approval time, require CA constraints and clientAuth purpose,
  enforce certificate validity, and bind the exact leaf SHA-256 fingerprint.
- Peer credential rotation requires current owner/broker proofs, replacement owner/broker proofs,
  explicit local confirmation, an atomic epoch change, and a node-signed rotation receipt. The
  production library exposes no raw credential-mutation API.
- A revoked peer can be recovered only through the separate owner-local `recovery-request` /
  `recovery-approve` ceremony. Replacement owner and broker keys must prove possession, local
  `--confirm` is mandatory, the trust epoch increases, and the original revocation remains in
  immutable recovery history. Active peers and remote callers cannot start this transition.
- Every action is signed by the paired broker key **and** the owner authority key. The signed body
  binds request, task, agent, node, capability, target, typed arguments digest, validity window,
  trust generation, and protocol version.
- Replay reservation and its redacted action context persist atomically. A separate immutable
  execution-start event must persist before dispatch; audit failure cannot fall through to a
  capability handler. A crash never causes an action to be automatically executed again. A
  singleton daemon lease safely marks prior open reservations `Indeterminate` on restart and keeps
  them spent.
- TLS 1.3 mutual authentication is mandatory when the LAN listener is enabled. Public, wildcard,
  and plaintext listeners are rejected. Atomic durable per-paired-peer and node-global request
  limits are enforced before authorization and replay reservation; reconnecting resets neither.
- Paired client trust reloads while the daemon runs. Sessions are bound to the exact certificate
  and trust epoch and close promptly after revocation, expiry, rotation, or trust-store loss.
- Only capabilities in both the local manifest and the paired peer's scope can run. The default
  manifest is read-only: `SystemInfo` and `ResourceStatus`.
- File and approved-action wire types are reserved for later hardening, but v0.1 configuration
  rejects advertising or executing them. There is no shell command string or code-upload path.
- The v0.1 daemon serves only on Unix, refuses to serve as root, and keeps identity/state owner-only.
- Pairing, revocation, and identity rotation are serialized by an owner-only admin lease; device
  identity rotation is refused while the daemon or a trusted peer is active and is audited.
- Remote execution fails closed if trust, replay, audit, time, or policy state cannot be verified.
- Remote authorization time is anchored to a durable high-water mark. A backwards wall-clock
  step beyond the tightly bounded local tolerance is denied and audited; lowering the checkpoint
  requires the daemon to be stopped plus explicit owner-local `clock acknowledge --confirm`.
- Optional offline update staging uses pinned, role-separated release and owner-approval Ed25519
  keys, a durable monotonic release counter, exact artifact hashing, rollback metadata, private
  no-follow staging, and digest-only decision audit. Staging never installs or executes anything.
- Optional `ProcessStatus` uses only an owner-defined logical process ID and a fresh signed local
  snapshot from a separate pinned key. Numeric PIDs, enumeration, commands, environments, paths,
  user identities, signals, and lifecycle controls are not exposed.
- Optional `ServiceStatus` uses only an owner-defined logical service ID and a fresh signed local
  snapshot from another role-separated key. The node invokes no service manager and exposes no
  unit files, commands, credentials, logs, configuration, enumeration, or lifecycle controls.
- Optional `RepositoryStatus` uses only an owner-defined logical repository ID and a fresh signed
  local snapshot from its own role key. The node never opens a work tree, invokes Git, accesses a
  remote, reads diffs or files, runs hooks, or mutates repository state.
- Optional Unix-only `FileRead` exposes only exact files copied into dedicated owner-controlled
  publication roots. Root descriptors are pinned at startup and every path component is opened
  relative to them without following links; hidden, credential-like, executable, hard-linked,
  special, unlisted, oversized, or out-of-root targets are denied. `FileWrite` remains unavailable.

See [Architecture](docs/ARCHITECTURE.md), [Pairing](docs/PAIRING.md),
[Identity](docs/IDENTITY.md), [Transport](docs/TRANSPORT.md),
[Capabilities](docs/CAPABILITIES.md), [Local Audit Export](docs/AUDIT.md), and
[Threat model](docs/THREAT-MODEL.md).

## Build and verify

Rust is the only runtime dependency.

```sh
cargo build --locked
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Initialize a node and render a conservative example configuration:

```sh
cargo run --locked -- init --data-dir /absolute/private/path --label workstation-1
cargo run --locked -- config-example --data-dir /absolute/private/path
```

The LAN listener is disabled until the owner supplies a TLS certificate/key, at least one approved
paired client CA and leaf certificate, and an exact private or loopback bind address. Pairing and
revocation commands are owner-local operations; run `sovereign-node --help` for the current CLI.

`sovereign-node audit export` emits a bounded, redacted, node-signed journal page. Verify an
exported page offline with `sovereign-node audit verify`, supplying the owner-retained NodeId,
device-key SHA-256, expected cursor, and prior verified chain anchor. The verifier reads only a
bounded no-follow regular file and does not open node state or contact a network.

Inspect the durable authorization-time checkpoint with `sovereign-node clock status`. If an owner
intentionally corrects the host clock backwards beyond policy, recovery is an explicit maintenance
operation: stop the daemon, verify the new time independently, then run
`sovereign-node clock acknowledge --confirm`. This never authorizes or retries an action.
`max_clock_rollback_secs` is part of the canonical policy digest, so an existing node adopting
this policy must increment its owner-controlled `policy_version` once before serving again.

## Capability defaults

| Capability | Default | Boundary |
| --- | --- | --- |
| `SystemInfo` | Enabled | Minimized OS, architecture, version, and logical CPU data |
| `ResourceStatus` | Enabled | CPU/RAM/disk/load, live bounded queue state, and optional signed accelerator, model, and health snapshots |
| `FileRead` | Optional, disabled by default | Unix-only exact-file publication from dedicated pinned read-only roots |
| `FileWrite` | Unavailable in v0.1 | Configuration and executor both reject it; read permission never grants write authority |
| `ExecuteApprovedAction` | Unavailable in v0.1 | Reserved schema; configuration rejects advertisement |
| `GpuStatus` / `EngineStatus` / `ModelStatus` | Optional, disabled by default | Requires the signed local resource adapter; aggregate or exact logical target only |
| `AgentGreenHealth` / `ActionBrokerHealth` | Optional, disabled by default | Requires its component-specific signed health adapter; never control or attestation |
| `ProcessStatus` | Optional, disabled by default | Requires a signed logical-process snapshot; raw PID targets are always denied |
| `ServiceStatus` | Optional, disabled by default | Requires a signed logical-service snapshot; observation only, with no service-manager access |
| `RepositoryStatus` | Optional, disabled by default | Requires a signed logical-repository snapshot; no repository or Git access |

The producer format and fail-closed freshness rules are documented in
[Signed local health snapshots](docs/HEALTH-SNAPSHOTS.md) and
[Signed local resource snapshots](docs/RESOURCE-SNAPSHOTS.md).
The logical-process format is documented in
[Signed local process-status snapshots](docs/PROCESS-STATUS-SNAPSHOTS.md).
The logical-service format is documented in
[Signed local service-status snapshots](docs/SERVICE-STATUS-SNAPSHOTS.md).
The logical-repository format is documented in
[Signed local repository-status snapshots](docs/REPOSITORY-STATUS-SNAPSHOTS.md).

## Offline and updates

Local status and owner control remain available without the central platform. New remote actions
are accepted only while cached signed trust remains current; stale, revoked, corrupt, or
unverifiable trust is denied. A reconnect does not retry an action with the same request ID.

The daemon has no downloader or self-update code. When pinned update keys are explicitly configured,
`sovereign-node update stage` verifies a local bundle and artifact against the release-role
signature, exact owner-approval signature, target OS/architecture, running version, artifact digest,
signed rollback checkpoint, and durable release-counter high-water mark. It then copies the
artifact into owner-private staging and audits the decision. Installation, post-install health
checks, and any signed rollback remain separate owner-operated steps.

## License

Apache-2.0. See [LICENSE](LICENSE).
