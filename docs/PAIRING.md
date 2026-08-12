# Pairing and Revocation

## Goal

Pairing establishes cryptographic trust between one physical node, its owner,
and an Action Broker. It always requires an owner to act at the node. Discovery,
knowledge of an IP address, possession of a pairing code, or a connection to the
same LAN is not enough to enroll a peer.

Pairing uses standard TLS 1.3 and Ed25519 implementations. The protocol composes
these established primitives; it does not define custom encryption or
signature algorithms.

## v0.1 implementation status

The shipping ceremony is owner-local CLI based. It displays the stable NodeId,
node device-key fingerprint, owner/broker key fingerprints, exact client-leaf
fingerprint, requested capability scope, signed trust expiry, a 256-bit random
challenge, and expiration. Owner and broker Ed25519 proofs cover that exact
transcript, including the node device-key digest, and `--confirm` is required
locally before the SQLite trust transaction commits. Revocation immediately
blocks every subsequent action through the per-action trust lookup and persists
across restart.

The remainder of this document is the target pairing contract. v0.1 does not
yet provide a GUI prompt, a client-generated challenge, a node-signed receipt,
recovery re-pairing under the same peer ID, or the full proof-of-possession
credential-rotation ceremony. Pending invitations
survive a daemon restart only until their original expiration and are not action
authority. The TLS verifier reloads owner-approved client trust and established
sessions recheck their exact leaf and trust epoch every 250 milliseconds.
All v0.1 pairing and revocation state changes share a non-blocking owner-only
admin mutation lease, preventing concurrent approval/revocation/identity-rotation
races. The daemon uses a separate lease, so local revocation remains available
while it is running.

## Identities displayed for approval

Before approval, the local node screen or terminal displays:

- stable NodeId;
- owner-chosen device label;
- node Ed25519 public-key fingerprint;
- operating system and architecture;
- Sovereign Node software version;
- capability manifest summary;
- proposed owner key fingerprint;
- proposed Action Broker key and transport-certificate fingerprints;
- trust generation to be created; and
- pairing expiration and one-time challenge words or digits.

The display must not include raw private keys, hardware serial numbers,
credentials, or other unnecessary hardware identifiers.

## Preconditions

- The owner has authenticated to the machine locally.
- The node identity store is initialized and readable only by the daemon
  account and owner administrator.
- The node is Unpaired, or the owner has explicitly started a replacement
  pairing after revocation.
- The local clock and cryptographic random number generator are available.
- No remote action endpoint is enabled for an unpaired peer.

## Owner-approved pairing flow

1. **Start locally.** The owner starts a pairing session through the local
   administrative interface. Remote callers cannot open a pairing window.
2. **Create a single-use invitation.** The node creates a random session ID,
   challenge, and short expiration. It records the session durably so a restart
   cannot make an old invitation valid again.
3. **Display node identity.** The node displays its NodeId, device public-key
   fingerprint, version, and capability summary on the local machine.
4. **Submit an enrollment proposal.** The prospective owner client provides the
   owner public key, Action Broker public key, intended transport credential,
   supported protocol version, and its own random challenge. The untrusted
   bootstrap channel accepts no action messages.
5. **Prove key possession.** The node, owner client, and broker each sign the
   canonical pairing transcript and both challenges with their Ed25519 keys.
   Standard library verification proves possession; the short displayed code
   is only an owner comparison aid and never substitutes for signatures.
6. **Compare out of band.** The owner compares the node fingerprint shown by the
   client with the fingerprint displayed locally, and compares the proposed
   owner and broker fingerprints with their expected values.
7. **Approve locally.** The node asks the local owner to approve the exact
   NodeId, key fingerprints, protocol version, trust generation, and requested
   capability policy. Timeout, cancellation, terminal loss, or any mismatch
   denies pairing.
8. **Commit atomically.** Only after local approval and all key proofs verify
   does the node atomically store the paired public keys, transport pins,
   capability policy, trust generation, and active status.
9. **Issue receipts.** The node signs a pairing receipt. The owner and broker
   retain the receipt, and the node writes a redacted audit event.
10. **Close bootstrap access.** The invitation is consumed, the pairing window
    closes, and further communication requires mutually authenticated
    transport using the paired identity.

Pairing is not complete if the local trust-store commit or audit write fails.
The runtime remains Unpaired and cannot execute remote actions.

## Pairing state machine

| State | Remote action behavior | Transition |
| --- | --- | --- |
| Unpaired | Reject | Local owner starts a pairing window |
| PairingPending | Reject | Local approval plus all cryptographic proofs |
| Paired | Apply normal authorization checks | Local revocation or quarantine |
| Quarantined | Reject | Local owner investigation and explicit recovery |
| Revoked | Reject | Fresh local re-pairing with a higher trust generation |

In the target design PairingPending expires automatically and unsuccessful proof
attempts consume it. v0.1 enforces the expiration but retains a failed invitation
until expiry; both signatures and local confirmation are still required.

## Revocation

Revocation is a local owner action and does not require the central platform to
be online. The node:

1. displays the identity and key fingerprints to be revoked;
2. asks for explicit local confirmation;
3. durably marks the trust record revoked;
4. invalidates owner, broker, and transport credentials from the old
   generation;
5. closes active sessions within the transport trust-check interval;
6. rejects queued and new remote actions, including actions signed before the
   revocation;
7. retains replay and audit history; and
8. records a durable revocation event without logging secret material.

Revocation is complete only when the new state is durable. A write failure
places the node in Quarantined state and denies remote actions.

An optional signed revocation message from an already trusted owner may make
remote emergency revocation possible, but it cannot silently pair a replacement
key. Local revocation remains available.

## Credential rotation

Routine rotation is an authenticated, owner-approved transition:

- the current and replacement key fingerprints are displayed locally;
- the current key and replacement key prove possession;
- the owner approves the exact transition locally;
- the trust generation increases;
- active sessions and old authorizations are invalidated; and
- the transition is durably audited.

For Action Broker rotation, the current broker, replacement broker, and owner
sign the rotation transcript. For owner-key rotation, the current owner and
replacement owner sign it. If a current private key is lost or suspected
compromised, the recovery path is local revocation followed by a fresh pairing;
there is no remote proof-of-possession bypass.

Node device-key rotation creates a signed continuity statement from the old key
to the new key and still requires local owner approval. If the old key is
unavailable, the node is treated as a new cryptographic identity and must be
paired again even when it retains the same physical device label.

## Audit events

The node records:

- pairing window created, expired, cancelled, or consumed;
- public-key fingerprints and NodeId, never private keys;
- proof and comparison outcome;
- local approval or denial;
- trust-store commit outcome and trust generation;
- revocation and quarantine;
- credential rotation; and
- session termination caused by a trust change.

Audit records include time, local actor category, reason code, and correlation
ID. Sensitive challenge values are not retained after the pairing safety
window.

## Failure and recovery rules

- A network disconnect does not approve or complete pairing.
- Reconnect requires a live, unconsumed invitation and a fresh channel.
- A node restart consumes or invalidates every PairingPending invitation.
- Duplicate enrollment messages are rejected.
- Unsupported protocol or identity versions are rejected.
- A mismatched NodeId, transcript, fingerprint, or signature is rejected and
  audited.
- Rate and size limits apply before expensive verification.
- Pairing never enables capabilities beyond the locally displayed and approved
  policy.
- Recovery never erases revocation, replay, or audit records merely to restore
  connectivity.
