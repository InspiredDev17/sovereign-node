# Sovereign Node Architecture

## Purpose

Sovereign Node is a local Rust daemon that executes narrowly authorized
capabilities on a computer or server owned by the operator. It is a controlled
execution endpoint for a Personal AI Platform; it is not an autonomous agent,
does not contain an LLM, and does not turn model output into shell commands.

The security boundary is:

    Personal AI Platform
             |
             | proposed action
             v
    authorization + Action Broker
             |
             | owner-and-broker signed action
             v
    authenticated Node Runtime
             |
             | local policy and capability checks
             v
    one local capability -> bounded result

Agent Green monitors node security independently. Sovereign Node may report its
health state, but it cannot disable, reconfigure, update, or impersonate Agent
Green.

## Security principles

1. A network location is not an identity. An IP address never establishes
   trust.
2. Pairing requires a person at the node to approve the displayed identities
   and public keys.
3. Transport authentication and action authorization are separate mandatory
   checks.
4. Every remote action is signed for one exact node, capability, target,
   argument digest, and expiration.
5. Both a registered owner key and a registered Action Broker key must sign the
   same canonical action envelope.
6. Capabilities are deny-by-default, explicitly configured, and least
   privileged.
7. Replay state and audit records survive process and node restarts.
8. Loss of trustworthy identity, policy, time, or replay state fails closed.
9. The daemon runs unprivileged and never exposes a general or root shell.
10. No Internet self-update, arbitrary code upload, or central secret storage is
    part of the design.

## Components

### Node Runtime

The daemon owns request handling and coordinates the security checks. It starts
only after validating its configuration, identity key, trust store, capability
policy, replay ledger, and audit store. Corrupt or unavailable security state
prevents remote action execution.

v0.1 acquires an owner-only, non-blocking singleton daemon lease before opening
the runtime. Only while holding that lease may startup reconcile nonterminal
reservations from a prior process to `Indeterminate`. Reconciliation never
dispatches or resumes the action. A separate short-lived admin mutation lease
serializes pairing, peer credential rotation, recovery re-pairing, revocation,
and device-key rotation without preventing live revocation checks in the
daemon. Pairing, peer rotation, and recovery use node-signed transcripts and
return node-signed receipts;
credential rotation additionally requires proofs from both current roles and
both replacement roles before its atomic trust-epoch change.
All three ceremonies validate the bounded client-certificate chain, CA constraints,
clientAuth purpose, validity window, and exact leaf digest at creation and
again at approval using established rustls WebPKI verification.

Recovery is a separate transition available only for a durably revoked peer.
It requires replacement owner/broker proofs plus local confirmation, binds the
old revocation and epoch, increments that epoch atomically, and preserves the
old revocation in immutable recovery history. It is never a LAN action.

### Identity and trust store

The identity subsystem holds a stable random NodeId, an Ed25519 device key pair,
device metadata, paired owner and broker public keys, transport credentials,
trust generation, and revocation state. Private keys remain local with
owner-only file permissions or an operating-system keystore when available.
The store contains no Personal AI Platform secret.

### Transport endpoint

The initial remote transport is TLS 1.3 with mutual authentication on an
explicitly configured private LAN address. The default administrative endpoint
is local-only. Public, wildcard, or Internet-facing exposure is not an
acceptable default. Transport details are in TRANSPORT.md.

### Authorization verifier

The verifier parses a bounded, versioned action envelope and checks:

- the protocol version is supported;
- RequestId, TaskId, and AgentId are present and well formed;
- NodeId equals this node;
- the capability and target are enabled by current local policy;
- the arguments digest matches the received canonical arguments;
- expiration has not passed and the local clock is trustworthy;
- the owner authority is active for the current trust generation;
- the registered owner and broker Ed25519 signatures both verify over the same
  canonical envelope;
- the RequestId and authorization digest have not already been consumed; and
- transport peer identity is currently paired and not revoked.

Signatures use established Ed25519 libraries. Arguments are hashed with SHA-256
after deterministic, versioned serialization. v0.1 uses a fixed-field postcard
encoding and rejects trailing bytes; it does not invent encryption,
signature, or key-derivation algorithms.

### Replay ledger

Before execution begins, the runtime durably reserves the RequestId together
with the authorization digest. The reservation and terminal result state are
persisted atomically. A repeated request cannot execute twice:

- the same RequestId and same digest returns a non-executing duplicate response;
  v0.1 stores terminal metadata and digests rather than response bodies;
- the same RequestId with a different digest is rejected as a conflict; and
- a different RequestId cannot reuse a single-use authorization.

The ledger is bounded by policy, but entries are never evicted before their
authorization lifetime plus the configured safety window. Resource pressure
must cause rejection, not replay protection bypass.

After an unclean daemon exit, a later daemon instance first acquires the
singleton lease and atomically records every nonterminal prior reservation as
`Indeterminate`. This frees bounded open-reservation capacity while preserving
the consumed RequestId and requiring owner reconciliation.

### Capability registry and executors

The registry contains only compiled-in capability kinds with an explicit local
policy instance. Each executor validates a typed argument schema and target
allowlist. There is no fallback from an unknown capability to a command shell.
ExecuteApprovedAction selects a preinstalled action identifier and fixed
executable; it cannot accept a shell string, executable path, script body, or
uploaded binary.

Before the authorization layer sees a decoded remote action, transport applies
atomic per-paired-peer and node-global admission limits stored in the local
state database. Their fixed one-minute windows survive reconnects and database
reopen, and they do not consume the action RequestId when rejecting excess
traffic. Neither counter advances unless both limits admit the request.

### Resource reporter

The reporter exposes bounded, non-sensitive summaries for CPU, memory, disk,
GPU, VRAM or unified memory, thermal state when supported, native inference
engine availability, loaded models, queue state, Agent Green health, and Action
Broker health. Unsupported or unverifiable values are reported as unknown, not
as healthy or zero.

CPU, RAM, disk, one-minute load, and queue measurements come from bounded local
runtime adapters. GPU, unified-memory, thermal, inference-engine, and loaded
model measurements may come from the optional component-specific signed local
resource snapshot contract. An empty GPU or model list means that no verified
entries are available; it is not proof that the machine has no GPU or models.

Agent Green remains independent. Its health is `Healthy`, `Degraded`,
`Unhealthy`, `Unavailable`, or `Unknown` and must come from a configured,
component-bound signed local health contract. Process presence alone is not
proof of health.

### Audit journal

Pairing, key changes, revocation, authorization decisions, replay rejection,
execution start and result, policy changes, and update decisions are written to
a durable local journal. Entries include identifiers and digests rather than
raw secrets, file contents, credentials, or sensitive arguments.

The journal is access controlled and may be hash-linked and node-signed for
damage evidence. It is not claimed to be tamper-proof against an attacker with
root access who can steal the node key and rewrite local storage. Export to an
owner-controlled log can improve survivability without granting control back to
the central AI.

## Action envelope

Every remote action carries at least:

| Field | Meaning |
| --- | --- |
| Protocol version | Exact message schema and canonicalization version |
| Request ID | Globally unique, single-use request identifier |
| Task ID | Owning platform task identifier |
| Agent ID | Identity of the proposing platform agent |
| User authority | Registered owner identity and current trust generation |
| Node ID | Exact destination node |
| Capability | Exact advertised capability kind and version |
| Target | Typed, policy-scoped target identifier |
| Arguments digest | SHA-256 of the canonical typed arguments |
| Issued time | Time at which authorization was created |
| Expiration | Hard deadline after which execution is forbidden |
| Replay value | Single-use nonce bound into the signatures |
| Policy version | Local policy version expected by the authorizer |
| Authorization | Owner and Action Broker key IDs plus both signatures |

The signatures cover every field above, including the arguments digest, with a
domain separator for the Sovereign Node action protocol. The received arguments
are validated against their typed schema and re-hashed locally before either
signature is accepted. Changing any action detail invalidates both signatures.

## Request lifecycle

1. The Personal AI Platform proposes an action. It has no direct node shell.
2. The owner authority and Action Broker independently approve the exact
   canonical action.
3. The paired client opens a mutually authenticated encrypted session.
4. The node validates transport identity, signatures, trust generation,
   expiration, NodeId, capability policy, arguments, version, and replay state.
5. The node durably reserves the RequestId.
6. One bounded executor performs the action as the unprivileged daemon account.
7. The node records a redacted result and returns a bounded response associated
   with the same RequestId.
8. Agent Green independently observes the host according to its own authority.

A failure at any step before execution produces a non-executing denial. A
failure after reservation records an indeterminate or failed result; it never
silently retries the action.

## Storage and privilege boundary

Security state is stored under an owner-controlled directory with restrictive
permissions and separate files or database namespaces for:

- device identity and private key reference;
- paired public keys and transport credentials;
- capability policy and policy version;
- revocation and trust generation;
- replay ledger; and
- audit journal.

The service account receives only the file and service permissions required by
enabled capabilities. Root-only operations are not smuggled through a helper.
If an installation later needs a privileged helper, that helper requires a
separate threat model, a fixed request schema, and explicit owner installation;
it is not part of the base daemon.

## Offline behavior

Local status and explicitly enabled local capabilities remain available through
the local owner endpoint while the central platform is disconnected. Remote
actions may be evaluated offline only when all required signatures, current
paired keys, trust generation, policy, replay state, and trustworthy time are
available locally.

If trust cannot be verified, security state is corrupt, revocation status is
ambiguous, or the clock is outside configured safety bounds, new remote actions
are rejected. Reconnection does not reset replay state or authorize queued
work. The remote peer must reauthenticate and resubmit a still-valid request.

The node persists a wall-clock high-water mark in the same SQLite state as its
replay ledger. Listener startup, authenticated request admission, and the
atomic replay-reservation transaction reject time earlier than that checkpoint
by more than `max_clock_rollback_secs`; ordinary observation can advance but
never lower it. A legitimate larger backwards correction requires the daemon
to be stopped and an owner-local `clock acknowledge --confirm`, which replaces
the checkpoint under both lifecycle leases and appends a digest-only audit
event. The acknowledgement does not consume, revive, or dispatch any action.
The rollback-rejection audit is latched until a safe time observation or owner
acknowledgement so a paired client cannot turn one clock fault into unbounded
duplicate audit growth.

## Updates

v0.1 implements owner-local offline verification and staging, not installation.
The optional `[updates]` policy pins separate release-role and owner-approval
Ed25519 public keys plus an artifact-size ceiling. `update stage` accepts only an
already-local strict JSON bundle and regular no-follow artifact, requires local
`--confirm`, verifies both signatures over the deterministic manifest, checks
the exact running-version transition and OS/architecture, streams and bounds the
artifact digest, and copies it into an owner-private staging directory.

The same SQLite transaction advances a persistent release-counter high-water
mark, pins the authority-key digests after first use, stores version and rollback
checkpoint metadata, and appends a digest-only accepted audit event. Denials are
also audited when the trust store is available. Staging output explicitly says
that installation was not performed. A schema migration preserves all existing
trust, revocation, replay, policy, and audit records.

The node contains no Internet downloader and performs no unattended update.
An update is an owner-supplied, versioned bundle containing hashes,
compatibility constraints, rollback metadata, and a signature
from a pinned release key. The implemented staging gate requires:

1. successful bundle signature and content verification;
2. explicit local owner approval of the displayed version transition;
3. compatibility and downgrade-policy checks;
4. a durable pre-update audit entry and rollback checkpoint.

Installation remains an explicit owner-operated step outside the daemon. A
future installer must additionally provide a post-update identity, policy, and
health verification before it can claim completion.

Rollback staging is itself a newly signed transition with a higher release
counter and must name the currently running version as its rollback checkpoint.
Rollback must not restore revoked trust, erase replay records, or reduce the
trust generation. Update transport is out of scope; the owner chooses how the
bundle reaches the machine.

## Non-goals

Sovereign Node does not provide:

- an LLM, planner, autonomous agent, or self-directed behavior;
- an unrestricted shell, root shell, arbitrary executable path, or arbitrary
  script execution;
- arbitrary file access or code upload;
- credential browsing or raw credential-file retrieval;
- implicit trust based on IP, DNS, hostname, or network proximity;
- an unauthenticated Internet listener;
- a mechanism to disable Agent Green; or
- automatic Internet self-update.
