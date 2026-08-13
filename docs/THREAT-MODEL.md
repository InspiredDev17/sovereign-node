# Threat Model

## Scope

This threat model covers the Sovereign Node Rust daemon, its local security
state, local administrative endpoint, private-LAN transport, pairing,
authorization, capability executors, resource reporting, audit, and
owner-supplied update verification.

Sovereign Node is not an autonomous AI and contains no LLM. Personal AI output
is treated as an untrusted action proposal until the node independently verifies
the exact owner and Action Broker authorization and local policy.

## Security objectives

The design aims to:

- execute only an unexpired, single-use action authorized by both the owner and
  Action Broker for this exact NodeId, capability, target, and arguments digest;
- prevent silent enrollment, stale trust, and network-location-based trust;
- contain each operation within an explicit least-privilege capability;
- preserve revocation and replay protection across disconnects and restarts;
- keep device, owner, broker, and central-service private credentials secret;
- minimize hardware and host information disclosure;
- produce a durable, redacted audit trail;
- reject new remote work when trust cannot be verified; and
- keep Agent Green independent and outside node control.

## Assets

- node Ed25519 private key and TLS private key;
- owner and broker public-key registration and trust generation;
- owner-approved capability policy;
- replay ledger and action result state;
- audit journal;
- authorized local files and service information;
- host availability and resource capacity;
- update signing policy and rollback state; and
- the integrity and independence of Agent Green.

## Actors and trust

| Actor | Trust decision |
| --- | --- |
| Local owner | Root of administrative approval; local account compromise remains a serious host threat |
| Personal AI Platform or model | Untrusted proposer; cannot directly authorize or execute |
| Action Broker | Required co-authorizer and authenticated transport peer; cannot override owner or local policy |
| Owner signing key | Required exact-action authority; cannot override broker or local policy |
| Sovereign Node | Enforcement point for identity, authorization, replay, policy, and execution |
| Capability executor | Trusted only for its documented narrow operation and OS privileges |
| Agent Green | Independent monitor; not controlled by Sovereign Node |
| LAN, DNS, routers, relay | Untrusted transport infrastructure |
| Update carrier | Untrusted; bundle signature and owner approval are required |

No single remote actor is sufficient. A valid owner signature, valid broker
signature, paired transport identity, active trust generation, and matching
local capability policy are all required.

## Assumptions

- The operating system provides a cryptographic random generator, correct
  process isolation, restrictive file permissions, and maintained
  cryptographic libraries.
- The owner can compare key fingerprints on the physical node during pairing
  and protect owner signing credentials.
- The node can obtain trustworthy time or detect when its time is too uncertain
  to validate expiration.
- The base daemon runs as an unprivileged account.
- Agent Green has its own authority and protection boundary.

When one of these assumptions cannot be established, the affected remote
operation fails closed.

## Threats and mitigations

| Threat | Required behavior |
| --- | --- |
| Attacker discovers the node IP | IP knowledge grants nothing; mTLS, paired identity, and signed action checks remain mandatory |
| Silent remote enrollment | Pairing starts and completes only with local owner interaction and displayed fingerprint comparison |
| LAN interception or modification | TLS 1.3 mutual authentication protects transport; application signatures protect each action |
| Malicious or compromised AI proposes a command | Model output has no authority; only typed capabilities with owner and broker exact-action signatures are considered |
| Broker compromise | Broker alone cannot act; owner signature and local policy are still required |
| Owner-key compromise | Owner key alone cannot act; broker signature, paired transport, and local policy are still required |
| Forged authorization | Ed25519 verification over canonical, domain-separated action bytes rejects it |
| Argument substitution | The node canonicalizes received arguments and compares their SHA-256 digest to the signed digest |
| Wrong-node routing | Signed NodeId must equal the local stable NodeId |
| Replay or duplicate delivery | Durable pre-execution RequestId reservation prevents a second execution across sessions and restarts |
| Expired queued request | Expiration is checked before reservation and again immediately before execution |
| Capability confusion | Capability name, version, target, policy version, and argument digest are signed and locally matched |
| Path traversal, ambient-root replacement, or link race | FileRead uses startup-pinned dedicated root descriptors, exact-file allowlists, component-wise no-follow opens, owner/type/mode checks, and hard-link denial; FileWrite is unavailable |
| General command injection | No shell exists; approved actions use a fixed executable and typed arguments without shell parsing |
| Arbitrary code upload | No upload-and-execute capability exists; file writes cannot create executable authority |
| Credential theft through status or logs | Reports and audit are schema-limited and redacted; security stores are excluded from file capabilities |
| PID reuse or process reconnaissance | ProcessStatus accepts only signed owner-defined logical IDs; numeric PIDs, enumeration, commands, paths, users, environments, and controls are denied |
| Service-manager exposure or lifecycle control | ServiceStatus consumes only a signed logical-ID snapshot; manager commands, enumeration, unit files, configuration, credentials, logs, PIDs, and controls are absent |
| Repository reconnaissance, credential access, or mutation | RepositoryStatus consumes only a signed logical-ID snapshot; paths, remotes, files, diffs, credentials, hooks, Git invocation, network access, and mutation are absent |
| Resource-exhaustion attack | Bounded frames, atomic durable per-peer and global admission, queues, concurrency, time, output, and backpressure cause rejection without security bypass |
| Disconnect ambiguity | Durable execution state returns recorded or Indeterminate outcome and never silently retries |
| Version downgrade | Locally allowed versions and versions bound into signatures reject unsupported or downgraded semantics |
| Revoked credential reuse | Revocation invalidates the trust record, rotation increments its generation, bound sessions close, and stale authorizations are rejected |
| Malicious update bundle | Pinned release signature, content hashes, version policy, local owner approval, audit, and rollback metadata are required |
| Automatic supply-chain compromise | The daemon contains no Internet updater or unattended install path |
| Agent Green suppression | Node lacks Agent Green control capability and reports only independently obtained signed health state; unverifiable state is Unknown |
| Audit tampering | Restrictive storage and optional node-signed hash linking provide damage evidence; external owner-controlled export improves survivability |
| Missing or corrupted pre-dispatch audit | Replay reservation stores a digest-bound redacted action context; the runtime must append one immutable execution-start event before calling any capability handler and fails closed on mismatch or persistence error |

## Local privilege and filesystem containment

The daemon is installed under a dedicated unprivileged account. Capability
policy grants only required roots, services, executables, and read interfaces.
Central AI credentials, SSH keys, cloud credentials, node private keys, trust
state, replay state, audit storage, and Agent Green secrets are always excluded
from remote file capabilities.

ExecuteApprovedAction directly invokes an owner-installed, integrity-pinned
binary with a fixed working directory, sanitized environment, typed arguments,
deadline, and output limit. It cannot receive a shell expression, arbitrary
path, interpreter option, script, environment override, or uploaded program.

The base design deliberately omits a privileged helper. Therefore operations
requiring root are unavailable rather than silently elevated.

## Offline and revocation risk

The node can validate paired keys and exact-action signatures locally, so loss
of Internet connectivity does not require an unsafe availability bypass.
Remote work is rejected when the node cannot verify trust, policy, replay state,
time, or storage integrity.

No offline system can learn a revocation event that has never reached it. This
residual risk is reduced by short action expirations, bounded credential
lifetime, local revocation, increasing trust generations, and requiring fresh
transport authentication after reconnect. The design does not claim instant
global revocation for an isolated machine.

## Host-compromise boundary

A remote LAN attacker, malicious model output, or compromised single
co-authorizer is within scope. Complete compromise of the host kernel, root
account, firmware, or physical storage can observe daemon memory, steal node
keys, alter executors, or erase logs and is not fully preventable by this
process.

Least privilege, operating-system keystores, verified update bundles, service
sandboxing, independent Agent Green monitoring, and external audit export
reduce impact and improve detection. They do not justify claiming resistance to
a fully malicious host administrator.

Denial of service cannot be eliminated: an attacker with LAN access may consume
some handshake or parsing capacity, and a local administrator can stop the
daemon. The goal is bounded degradation with no authorization bypass.

## Privacy boundary

Identity and resource reports minimize stable hardware identifiers. Public or
unpaired responses never disclose serial numbers, MAC addresses, firmware
UUIDs, filesystem layout, usernames, process command lines, secrets, loaded
model paths, or repository credentials. The owner must explicitly enable any
additional disclosure through local policy.

## Audit limitations

Audit records are durable and redact sensitive payloads. A local hash chain or
node signature can reveal many forms of accidental corruption and post-export
modification. It cannot prove integrity after a root attacker steals the node
key and controls all local storage. Security documentation and operator output
must describe this honestly.

## Required security tests

This table is the release-gate target matrix. The current automated suite covers
pairing approval and both remote key proofs, revocation persistence, replay and
duplicates across reopen/reconnect, forged/expired/wrong-node/capability/version
denials, traversal rejection before reservation, bounded replay exhaustion,
restart identity stability, node-signed pairing receipts, and credential epoch
rotation requiring current and replacement owner/broker proofs plus local
confirmation. It also covers revoked-peer recovery requiring replacement
owner/broker proofs and local confirmation, forged/expired recovery denial,
epoch advancement, old-credential invalidation, preserved revocation history,
repeat revocation, and restart durability. Session closure,
TLS 1.3 handshake, exact-leaf matching, and live pairing/revocation/rotation
reload are covered with real loopback sockets and ephemeral test certificates.
Certificate enrollment tests cover exact fingerprint mismatch, malformed DER,
non-CA trust anchors, wrong issuer, serverAuth-only leaves, missing TLS-signing
usage, expired leaves, approval-time expiry, and a valid intermediate chain.
Full filesystem-race cases for reserved file/action capabilities remain explicit
pre-enablement gates; those capabilities are unavailable in v0.1. Offline update
tests cover pinned role separation, exact signatures and digest, local
confirmation, target/version/rollback checks, bounded no-follow staging,
owner-only output, monotonic counter replay/collision/authority resistance,
rejection audit, restart durability, and schema migration. Installation and
post-install health verification remain owner-operated and are not claimed by
these tests. The suite also verifies singleton/admin lease separation and
daemon-lease-only crash reconciliation to `Indeterminate` without retry.
ProcessStatus tests cover exact signed logical targeting, role separation,
freshness, forgery, duplicate IDs, unknown targets, symlink denial, bounded
privacy output, child-enumeration denial, and raw-PID rejection before replay
reservation.
ServiceStatus tests cover exact signed logical targeting, role separation,
freshness, forgery, duplicate IDs, unknown targets, strict-schema privacy,
symlink denial, bounded output, and end-to-end denial without any service-manager
or lifecycle-control path.
RepositoryStatus tests cover exact signed logical targeting, role separation,
freshness, forgery, duplicate IDs, inconsistent states, strict-schema privacy,
symlink denial, bounded counts, untracked-summary minimization, and end-to-end
denial without any repository, Git, network, hook, or mutation path.
FileRead tests cover exact allowlisting, bounds and offsets, digest output,
startup root-descriptor pinning, traversal denial, unlisted targets, symlinked
files and directories, hard links, executables, directories, broad roots,
hidden and credential-like names, and the continued unavailability of
FileWrite.
Action-audit tests cover redacted structured context, digest binding, durable
restart recovery, exact-once execution-start evidence, wrong-fingerprint and
terminal-state rejection, tampered-context denial, and schema-v9 migration that
preserves older replay/audit history without fabricating context.
Local audit-export tests cover strict page bounds, full-chain verification,
cursor and anchor semantics, domain-separated node signatures, key matching,
multi-page continuity, action-context linkage, raw-value exclusion, and event
or payload tamper rejection. Offline-verifier tests additionally cover explicit
NodeId/device-key/cursor/anchor pins, malformed or oversized JSON,
nonprogressing pages, concise continuation receipts, and no-follow regular-file
input.
Identity-proof tests cover requester nonce binding, short expiry, future and
expired rejection, strict nested JSON, exact NodeId/key pins, manifest and
policy mutation, forged signatures, bounded no-follow input, stable trust-set
ordering, epoch sensitivity, and rejection of expired, revoked, duplicate, or
wrong-node trust records. Coherent-state tests require the configured policy to
match the durable activated version and digest, reject inactive or mismatched
bindings, and verify trust, policy, and audit chain in one SQLite snapshot.
Transport integration tests use real loopback TLS 1.3 sessions to interrupt a
frame before canonical decoding, prove that no replay or action-audit record was
created, reconnect with the complete signed envelope, verify the node-signed
success, and confirm a second reconnect returns a non-executing duplicate. A
second path disconnects after full delivery without reading the response,
requires durable execution-start and terminal evidence, then proves the
reauthenticated retry is duplicate-only and leaves that action record unchanged.
Authenticated framing tests reject oversized declared lengths and trailing data
before authorization, prove no action-audit record is created, and then execute
the untouched canonical envelope with the same RequestId exactly once.
Authenticated rate-limit tests exhaust the durable peer window, reconnect twice
with a fresh valid envelope, and prove both admissions fail before replay or
action-audit state is created.
Credential-rotation transport tests additionally prove an established old TLS
session closes after the durable epoch change, the prior leaf cannot recover a
paired session, and only the replacement leaf binds to the incremented epoch.

Tests use isolated temporary state and deterministic clocks where appropriate.
They assert that denied requests produce no capability side effect.

| Scenario | Acceptance criterion |
| --- | --- |
| Pairing | Remote action remains disabled until local approval and owner/broker proofs over the node-bound transcript succeed; the node signs the transcript and resulting receipt |
| Revocation | Revocation survives restart, rejects old credentials and queued work, and closes bound TLS sessions within the trust-check interval |
| Replay | A consumed authorization or replay value cannot execute under a new delivery |
| Forged authorization | A modified field, digest, owner signature, or broker signature is rejected |
| Expired authorization | Requests at or beyond expiration are rejected before execution; clock uncertainty fails closed |
| Host clock rollback | A durable high-water mark rejects material backwards movement at startup, admission, and replay reservation; only a stopped-daemon, owner-confirmed, audited local acknowledgement can lower it |
| Wrong node | A correctly signed action for another NodeId is rejected |
| Replayed identity statement | V1 remains informational; V2 requires a fresh requester nonce, short expiry, strict signature verification, and owner-retained NodeId/key pins |
| Alternate identity-proof config | Proof generation refuses inactive, rolled-back, advanced-but-unactivated, or same-version-remapped policy and reads trust/policy/audit from one SQLite snapshot |
| Capability mismatch | Unknown, disabled, wrong-version, wrong-target, or wrong-policy capabilities are rejected |
| Disconnect | Loss before reservation has no effect; loss after reservation cannot cause automatic retry |
| Reconnect | Peer reauthenticates, trust is rechecked, and queued expired or revoked actions remain denied |
| Duplicate request | Same RequestId and digest never executes twice; conflicting digest is rejected |
| Version mismatch | Unsupported major version, schema ambiguity, and downgrade attempt are rejected |
| Resource exhaustion | Oversized input, full queue, excessive concurrency, and output pressure yield bounded rejection without evicting security state |
| Unauthorized file access | Parent traversal, absolute escape, symlink, sensitive store, device, and disallowed root are rejected without content disclosure |
| Node restart | NodeId, trust generation, revocation, replay reservation, and audit state persist; incomplete side effects become Indeterminate, not retried |
| Credential rotation | All current and replacement owner/broker proofs plus local confirmation are required; old sessions and authorizations stop working after the atomic durable epoch change, and the node signs the receipt |
| Pairing recovery | Only an explicitly revoked peer can enter recovery; replacement owner/broker proofs and local confirmation advance the epoch without erasing the prior revocation, replay, or audit history |
| Offline update staging | Separate pinned release/owner signatures, local confirmation, exact digest/target/version/rollback checks, and a durable higher counter are required; output remains inert and uninstalled |

Additional tests cover malformed canonical encodings, TLS peer mismatch,
pairing-window expiry, duplicate enrollment, corrupt state, untrustworthy time,
binary-digest change, status redaction, and inability to control Agent Green.

Tests must include both unit-level policy checks and integration tests that
restart the daemon against durable state. Resource-exhaustion and filesystem
tests run with hard time and space bounds so the test mechanism does not itself
create unsafe host pressure.

## Security invariants

The following properties must remain true across future features:

1. Transport reachability never equals authorization.
2. Neither AI output, owner signature, nor broker signature alone can execute.
3. The local capability policy can only narrow remote authority.
4. One authorization produces at most one execution attempt.
5. Revocation and restart never roll trust or replay state backward.
6. Unknown identity, version, time, health, or policy state is not treated as
   trusted or healthy.
7. No remote feature can disable Agent Green, install arbitrary code, reveal
   credential files, or create a general shell.
8. Updates remain signed, owner-approved, versioned, rollback-aware, and
   audited, with no automatic Internet downloader.
