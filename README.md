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
  certificate pinning, expiry, revocation, and durable audit records.
- Every action is signed by the paired broker key **and** the owner authority key. The signed body
  binds request, task, agent, node, capability, target, typed arguments digest, validity window,
  trust generation, and protocol version.
- Replay reservation and audit-start persistence occur atomically before dispatch. A crash never
  causes an action to be automatically executed again. A singleton daemon lease safely marks
  prior open reservations `Indeterminate` on restart and keeps them spent.
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

See [Architecture](docs/ARCHITECTURE.md), [Pairing](docs/PAIRING.md),
[Identity](docs/IDENTITY.md), [Transport](docs/TRANSPORT.md),
[Capabilities](docs/CAPABILITIES.md), and [Threat model](docs/THREAT-MODEL.md).

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

## Capability defaults

| Capability | Default | Boundary |
| --- | --- | --- |
| `SystemInfo` | Enabled | Minimized OS, architecture, version, and logical CPU data |
| `ResourceStatus` | Enabled | Aggregate CPU/RAM/disk and explicit unsupported health fields |
| `FileRead` / `FileWrite` | Unavailable in v0.1 | Reserved schema; configuration rejects advertisement |
| `ExecuteApprovedAction` | Unavailable in v0.1 | Reserved schema; configuration rejects advertisement |
| Process/service/GPU/engine/model/repository status | Disabled | Explicit adapter/allowlist required |
| Agent Green / Action Broker health | Disabled | Sanitized read-only status; never control or attestation |

## Offline and updates

Local status and owner control remain available without the central platform. New remote actions
are accepted only while cached signed trust remains current; stale, revoked, corrupt, or
unverifiable trust is denied. A reconnect does not retry an action with the same request ID.

The daemon has no downloader or self-update code. `update.rs` only verifies a local artifact against
a release-role signature, an exact owner-approval signature, target OS/architecture, current
version, artifact digest, and monotonic release counter. Installation, health checks, and rollback
remain an explicit owner-operated process.

## License

Apache-2.0. See [LICENSE](LICENSE).
