# Node Identity

## Identity layers

Sovereign Node keeps distinct identity layers:

1. **NodeId:** a stable, random, non-secret identifier for protocol routing.
2. **Device cryptographic identity:** an Ed25519 key pair that proves control of
   this node identity.
3. **Device description:** owner-chosen label plus privacy-minimized platform
   facts.
4. **Registration:** owner and Action Broker public keys, mutually authenticated
   transport pins, trust generation, and status.
5. **Capability manifest:** the exact locally enabled operations and schema
   versions.

None of these layers makes an IP address an identity. Network addresses may
change and are never used as proof of trust.

## v0.1 implementation status

v0.1 persists a random stable NodeId, installation ID, owner label, rotation
counter, and Ed25519 device key in an owner-only local identity document. The
legacy `identity` CLI emits a device-signed informational V1 registration with
public identity, privacy-minimized platform/hardware facts, software version,
basic capability manifest, coarse `Unpaired`/`Trusted` status, and generation
time. That V1 snapshot has no requester challenge or expiry and must not be
treated as fresh proof of current trust.

The `identity-proof` CLI implements the fresh V2 statement. It binds the full V1
registration, an exact capability-manifest digest, the canonical local-policy
digest, a privacy-preserving active-peer trust-set digest, a requester-generated
32-byte challenge, issue time, and an expiry no more than five minutes later.
The companion `identity-verify` command uses strict bounded JSON and requires an
owner-retained NodeId, owner-retained node-key SHA-256, and the original
challenge. It opens no node state or network and emits a concise receipt only
after freshness, structure, digest, pin, and strict Ed25519 verification.

V2 reports the active peer count and maximum active peer trust epoch. The latter
is a summary of per-peer epochs, not a fabricated node-global trust generation.
The signed trust-set digest changes when an active peer's identity, approved
manifest, epoch, pairing, or expiry changes while excluding raw peer IDs, keys,
and labels. Proof creation briefly holds the local admin-mutation lease so the
trust set cannot change during its snapshot.

The same SQLite read snapshot verifies the complete audit chain and reads the
durable active policy binding. `identity-proof` fails closed when policy has
never been activated, or when the selected config reuses an active version with
a different digest, advances beyond the active version, or rolls back below it.
The operator must first start the daemon with the intended valid configuration
so normal monotonic policy activation succeeds. Proof generation itself never
activates or changes policy.

The v0.1 rotation CLI requires local confirmation, serializes against every
pairing/revocation mutation, refuses to run while the daemon or any trusted peer
is active, preserves NodeId, and creates a dual-signed old/new-key continuity
binding. Before replacing `identity.json`, it durably stores a versioned pending
transaction and the started audit event. The replacement is descriptor-checked,
atomically renamed and directory-synced; the completion audit and pending-record
removal then commit together. On restart, the CLI deterministically recognizes
either the old key plus staged file or the already-swapped new key, completes
exactly once, and returns the continuity evidence. It does not rotate TLS
credentials or silently preserve remote trust; peers must be re-established.

## Stable NodeId

On first initialization, the daemon obtains at least 128 bits from the operating
system cryptographic random number generator and encodes them in a standard
UUID-compatible or equivalently unambiguous textual form. It does not derive
NodeId from a MAC address, disk serial number, hostname, username, IP address,
or device public key.

NodeId remains stable across ordinary restarts, software updates, network
changes, and device-key rotation. Cloning the identity store is forbidden:
restoring an image to a second machine requires generating a new NodeId and
pairing it separately. If duplicate identity is detected, the node enters
Quarantined state.

## Device cryptographic identity

The node generates an Ed25519 key pair with a maintained cryptographic library.
The private key:

- is created from the operating system cryptographic random source;
- never leaves the node in plaintext;
- is stored with restrictive service-account permissions or referenced from an
  operating-system keystore;
- is never sent to the Personal AI Platform, Action Broker, or Agent Green;
- is not reused as an owner or broker key; and
- is not logged, included in resource reports, or exposed by FileRead.

The public key and its fingerprint are displayed during pairing. A fingerprint
is a standard digest of the canonical public-key encoding and is always shown
with its algorithm and version.

Possession of the node private key authenticates the node but does not authorize
an action. Owner and broker signatures plus local capability policy remain
mandatory.

## Device description

The local identity record may contain:

- owner-chosen device label;
- operating system family and supported version;
- CPU architecture;
- broad hardware capability classes;
- Sovereign Node software and protocol versions; and
- installation instance creation time.

Hardware facts are informative, not authentication factors. Public identity
responses omit serial numbers, MAC addresses, firmware UUIDs, filesystem UUIDs,
account names, exact storage paths, and other stable hardware identifiers
unless the owner explicitly enables a narrowly justified local disclosure.

## Public identity statement

Implemented fresh V2 identity proof contains the fields described in the v0.1
status section above. The richer canonical statement below remains target
architecture for Sovereign-AI-Contracts:

- identity schema version;
- NodeId;
- Ed25519 public key and fingerprint;
- device label;
- OS and architecture;
- privacy-minimized hardware summary;
- software and protocol versions;
- capability-manifest digest;
- current trust status and trust generation;
- issuance time and short expiration; and
- a requester challenge.

The node signs the canonical statement with its device key. The challenge and
short expiration prevent a captured statement from serving as fresh proof.
Before pairing, the statement supports owner comparison only; it does not make
the node trusted.

Generate and verify a fresh statement as follows. The requester must generate a
new unpredictable challenge for each freshness check and retain expected pins
outside the returned proof.

```text
sovereign-node identity-proof \
  --config /absolute/path/to/sovereign-node.toml \
  --challenge-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --ttl-seconds 60

sovereign-node identity-verify \
  --input /absolute/path/to/identity-proof.json \
  --expected-node-id 11111111-1111-4111-8111-111111111111 \
  --expected-node-key-id-sha256 2222222222222222222222222222222222222222222222222222222222222222 \
  --expected-challenge-hex 1111111111111111111111111111111111111111111111111111111111111111
```

A captured proof can still be presented during its signed validity window if a
requester reuses the same challenge. Freshness therefore depends on a new
requester nonce and local tracking of which nonce was issued. V2 does not claim
TPM-backed attestation or prove that a root-compromised host reported honestly.
It is also a point-in-time snapshot: later policy, trust, or revocation changes
require a newly challenged proof.

## Trust status

Trust status is explicit:

| Status | Meaning |
| --- | --- |
| Unpaired | No owner and broker registration is active |
| PairingPending | A local, expiring pairing ceremony is in progress |
| Paired | Active owner, broker, and transport credentials are durably stored |
| Quarantined | Identity or trust integrity is uncertain; remote execution is denied |
| Revoked | The prior trust generation was explicitly invalidated |

The status is reported with a monotonically increasing trust generation.
Authorizations name the generation they were created under. An authorization
from any older or future generation is rejected.

## Registration record

An active registration contains:

- NodeId and node public-key fingerprint;
- owner key ID, algorithm, public key, and authority scope;
- Action Broker key ID, algorithm, public key, and authority scope;
- mutually authenticated transport certificate or public-key pins;
- capability-policy digest and version approved during pairing;
- supported action-protocol versions;
- trust generation;
- creation, rotation, and optional administrative expiry times; and
- current status and revocation reason code.

Only public credentials are registered. Central API tokens, model-provider
credentials, SSH private keys, owner private keys, and broker private keys are
not stored by the node.

## Capability manifest identity

The implemented legacy action manifest is part of node identity but not a grant
from the remote peer. It contains only a manifest version, capability enum list,
and generation time; the signed V2 proof separately binds its digest and the
canonical local policy digest. It does not yet contain target summaries,
argument/result schema digests, availability reasons, or resource limits.

The development-only workload manifest adds domain-separated NodeId, key and
identity generation, software/protocol/contract revisions, expiry, basic
hardware facts, truthful sandbox fields, and locally trusted service inventory.
It is unit-tested but is not yet emitted by the daemon or canonicalized in
Sovereign-AI-Contracts.

The locally loaded policy is authoritative. A stale advertisement cannot enable
a removed capability, and a remote request cannot expand the manifest. A
manifest change increments the policy version and is audited.

## Key rotation and recovery

Routine device-key rotation is owner-approved locally. When the old key is
healthy, it signs a standards-based continuity statement binding NodeId, old
public key, new public key, trust generation, and time. The new key signs the
same statement. The owner confirms both fingerprints locally, paired parties
register the new public key, and all old sessions close.

If the old key is unavailable or suspected compromised, continuity is not
assumed. The node is revoked or quarantined and requires a fresh local pairing.
Keeping the same NodeId is an owner recovery decision recorded in the audit; it
does not preserve old remote authorizations.

Peer credential recovery is separate from node device-key recovery. For a
durably revoked peer, v0.1 can retain the same pairing relationship ID only
through the owner-local recovery ceremony: replacement owner and broker keys
prove possession, the node signs the exact revocation-bound transcript, the
trust epoch increases, and immutable recovery history retains the prior
revocation. No remote action or revoked key can authorize that transition.

Backups of identity state must be encrypted and owner controlled. Restoring a
backup never rolls trust generation, revocation records, replay state, or audit
state backward. If consistency cannot be proven, the node fails closed and
requires local recovery.

## Versioning

Identity statements, keys, manifests, registrations, and signatures each carry
an algorithm or schema version. Unknown mandatory fields, unsupported
algorithms, incompatible major versions, or downgrade attempts are rejected.
v0.1 validates fixed versions and does not negotiate an application protocol.
Any future negotiation may select only a mutually supported, locally allowed
version and may not silently reinterpret signed bytes.
