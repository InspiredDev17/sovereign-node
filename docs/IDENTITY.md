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
`identity` CLI emits a device-signed informational registration with public
identity, privacy-minimized platform/hardware facts, software version, basic
capability manifest, coarse `Unpaired`/`Trusted` status, and generation time.
That snapshot has no requester challenge or expiry and must not be treated as
fresh proof of current trust. The richer challenge-bound registration and trust
state model below is the target contract.

The v0.1 rotation CLI is narrower than the target ceremony: it requires local
confirmation, serializes against every pairing/revocation mutation, refuses to
run while the daemon or any trusted peer is active, preserves NodeId, writes a
dual-signed old/new-key continuity binding, and appends digest-only rotation
intent and completion audit events. A surviving intent without completion makes
an interrupted rotation visible to the owner. It does not rotate TLS credentials
or silently preserve remote trust; the daemon must be restarted and peers
re-established explicitly.

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

The node can produce a signed identity statement containing:

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

The manifest is part of node identity but not a grant from the remote peer. It
contains each enabled capability name and version, target-scope summary,
argument-schema digest, result-schema digest, resource limits, and local policy
version. The node signs manifest responses with its device key.

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

Backups of identity state must be encrypted and owner controlled. Restoring a
backup never rolls trust generation, revocation records, replay state, or audit
state backward. If consistency cannot be proven, the node fails closed and
requires local recovery.

## Versioning

Identity statements, keys, manifests, registrations, and signatures each carry
an algorithm or schema version. Unknown mandatory fields, unsupported
algorithms, incompatible major versions, or downgrade attempts are rejected.
Version negotiation may select only a mutually supported, locally allowed
version; it may not silently reinterpret signed bytes.
