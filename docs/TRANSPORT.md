# Authenticated Transport

## Security objective

Transport provides confidentiality, integrity, peer authentication, bounded
framing, and downgrade resistance. It does not authorize a capability.
Sovereign Node validates the complete signed action locally even after a
mutually authenticated connection succeeds.

Knowing the node hostname, DNS record, or IP address grants no trust.

## v0.1 implementation status

v0.1 implements an opt-in, exact private/loopback TCP listener with rustls
TLS 1.3 only, mandatory client certificate validation, exact paired leaf digest,
bounded length-prefixed postcard frames, connection/action semaphores, and read,
handshake, and write deadlines. Every authenticated request is atomically
checked against durable per-peer and node-global one-minute fixed-window limits
after bounded decoding and before authorization or replay reservation.
Reconnecting or reopening the state store does not reset either limit; a
backwards clock step beyond the configured zero-to-sixty-second tolerance fails
closed against a durable high-water mark. The default tolerance is five seconds.
Every admitted frame is authorized again
against current durable trust. Local administration is CLI-only, not a Unix
socket. Paired client trust snapshots reload every 250 milliseconds. New and
rotated pairings become eligible for a new handshake without daemon restart.
Every established session is bound to its exact leaf digest and trust epoch and
is rechecked on the same interval while reading, waiting for runtime work, and
writing. Revocation, expiry, rotation, malformed trust, or an unavailable trust
store closes the session. Application version negotiation remains target work.
The node server certificate must be provisioned to clients through a separate
owner-controlled channel and does not reload in v0.1.

The clock checkpoint is advanced at listener startup and inside authenticated
admission/replay transactions. It never moves backwards automatically. Clock
rollback recovery is intentionally unavailable over this transport: the owner
must stop the daemon, verify local time, and invoke the audited local CLI
acknowledgement with explicit confirmation.

An action already durably dispatched is not cancelled solely because its
session closes; it finishes under the normal bounded runtime and terminal-state
rules. Work that was only queued rechecks current trust before reservation and
cannot execute under the invalidated session epoch.

Loopback socket tests generate ephemeral certificates at test time and prove
TLS 1.3 negotiation, rejection when the client certificate is absent, and exact
paired-leaf matching even when a different leaf chains to the trusted CA.

Only one v0.1 daemon may hold the node's owner-only singleton lease. At startup,
after acquiring that lease, it converts prior nonterminal replay reservations to
durable `Indeterminate` metadata and never retries them. Merely opening the store
from a status or administration command cannot perform this reconciliation.

## Endpoints

### Local administration

Pairing, revocation, recovery, capability-policy changes, and update approval
use a local owner endpoint. In the target design, on Unix-family systems this should be a
permission-restricted Unix domain socket. An equivalent authenticated local IPC
mechanism is used on other platforms.

Local access is not automatically privileged. The endpoint verifies operating
system peer credentials, applies owner-configured permissions, rate limits
requests, and audits security-sensitive changes. Remote interfaces cannot call
local-only administrative methods.

### Private-LAN runtime

LAN service is opt-in. The owner configures one specific private or loopback
address and port. Acceptable address classes include loopback, RFC 1918 IPv4,
IPv6 unique-local addresses, and an explicitly selected link-local interface.
The daemon refuses a public address. Wildcard binding is disabled by default and
must not be used as a shortcut around interface selection.

Network classification is defense in depth, not authentication. Every runtime
connection still requires TLS 1.3 mutual authentication with credentials
created by owner-approved pairing.

No unpaired action endpoint and no unauthenticated Internet listener exist. A
firewall is recommended but is not treated as the sole security boundary.

## TLS profile

The implementation uses a maintained TLS library, such as rustls, with:

- TLS 1.3;
- certificate and public-key algorithms allowed by current local policy;
- forward-secret standard cipher suites supplied by the library;
- both server and client authentication;
- node certificate or public-key pinning to the paired NodeId;
- client certificate or public-key pinning to the paired Action Broker
  transport identity;
- certificate validity and usage checks;
- hostname-independent NodeId binding at the application layer; and
- no anonymous, plaintext, legacy TLS, or silent downgrade mode.

TLS private keys remain local. Application Ed25519 identity keys should be
separate from TLS keys so rotation and purpose are explicit. Certificate
issuance may use an owner-controlled private CA or pinned self-managed
certificates; the application is not coupled to a commercial certificate
service.

Owner-local pairing treats the configured client certificate PEM as a bounded
leaf-first chain. Before any trust commit it validates CA constraints, every
DER object, leaf clientAuth and signing usage, the chain to the submitted CA,
current certificate validity, and the exact leaf fingerprint. The same checks
run again at local approval so a certificate that expires during a ceremony is
not enrolled. Only the CA and exact leaf digest become active transport trust;
intermediates remain short-lived ceremony evidence.

Revoking a paired credential invalidates its trust record and closes existing
sessions. Rotation increments the trust generation and closes sessions bound to
the prior generation. Owner-local recovery likewise installs a replacement leaf
pin and increments the generation only after durable revocation-bound approval;
the revoked leaf never becomes valid again. TLS session resumption must not
outlive the credential or generation that created it.

## Application authentication

After TLS succeeds, the node binds the session to:

- paired peer key ID;
- exact NodeId;
- active trust generation;
- negotiated protocol version; and
- transport-certificate digest.

Each action is then independently verified using the owner and Action Broker
Ed25519 signatures described in ARCHITECTURE.md. A valid client certificate
without valid action signatures is insufficient. Valid action signatures over
a different NodeId, expired trust generation, or disabled capability are also
insufficient.

This layered check prevents a TLS terminator, compromised network credential,
or routing error from converting connectivity into execution authority.

## Protocol framing and limits

Messages use a deterministic, versioned schema. Every frame has:

- protocol major and minor version;
- message type;
- declared body length;
- correlation or RequestId where applicable; and
- a bounded canonical body.

The node rejects an oversized frame, duplicate mandatory field, unknown
critical field, malformed canonical encoding, excessive nesting, invalid UTF-8
where text is required, or trailing data. Limits are enforced while reading,
before allocation proportional to attacker-controlled lengths.

Request, argument, file-transfer, response, and audit-detail sizes have
independent policy limits. Compression is off by default and, if later enabled,
must enforce decompressed-size and ratio limits.

## Connection lifecycle

1. Accept only on a configured local or private endpoint.
2. Apply connection count, handshake time, and input-size limits.
3. Complete TLS 1.3 mutual authentication.
4. Resolve the client credential to an active paired trust generation.
5. Negotiate one locally allowed application-protocol version.
6. Process bounded requests; authorize each action independently.
7. Use deadlines and cancellation without converting cancellation into retry.
8. Recheck certificate binding, trust epoch, revocation, expiry, and trust-store
   availability at most every 250 milliseconds while a session is active.
9. Close on authentication failure, malformed framing, revocation, rotation,
   trust-generation change, trust-state loss, or repeated policy violations.

Authentication failures return minimal error categories and never reveal which
key, NodeId, capability, path, process, or service would have been valid.

## Disconnect, reconnect, and duplicate delivery

A connection is not an execution transaction. The replay ledger is the
authoritative request state.

- Disconnect before durable RequestId reservation means no execution occurred.
- Disconnect after reservation does not permit an automatic second execution.
- Reconnect requires a new mutually authenticated session.
- A resubmitted identical RequestId and authorization digest returns a
  non-executing duplicate status. v0.1 retains terminal metadata/digests, not
  response bodies, so operator reconciliation may be required.
- A duplicate RequestId with different content is rejected.
- A queued request that expires while disconnected is rejected.
- Reconnection never resets revocation, replay, queue, or rate-limit state.

The transport test harness exercises this boundary over real TLS 1.3 loopback
connections: a partial-frame disconnect creates no reservation, the complete
signed request succeeds after reauthentication, and its next delivery returns
only a duplicate response. It also drops a client after full request delivery
but before response receipt, confirms the durable execution record completed,
then verifies the retried envelope is duplicate-only and cannot create another
execution attempt.

Authenticated malformed-frame tests send an oversized declared length and a
fully signed action with trailing bytes. Both connections close with a framing
error before authorization or replay reservation; the canonical form of that
same RequestId remains fresh and succeeds on a new mutually authenticated
session.

Credential-rotation transport tests hold an authenticated old TLS session open
across an atomic trust-epoch and leaf-pin change. The old session closes within
the trust-check interval, reconnecting with the prior leaf resolves to no paired
session, and only the replacement leaf resolves to the incremented epoch.

For an action whose side effect cannot be proven after a crash, the result is
Indeterminate and requires owner reconciliation. The runtime must not guess and
execute it again.

## Version negotiation

The client proposes supported protocol versions, and the node chooses only from
its locally allowed set. The selected version is bound into the session and
each signed action. Unsupported major versions, disallowed legacy versions,
schema disagreement, or downgrade below local policy terminates the request.

Compatibility cannot change signed field meaning. New optional response fields
may be ignored only when the negotiated schema explicitly permits that
behavior.

## Resource-exhaustion controls

Before cryptographic and capability work, the endpoint enforces:

- maximum concurrent connections and handshakes;
- atomic durable per-peer and node-global request rates;
- read, handshake, queue, execution, and idle deadlines;
- bounded frame and argument sizes;
- bounded in-memory queues;
- bounded result size and streaming backpressure; and
- fair concurrency limits for expensive capabilities.

When either v0.1 request limit is reached, the connection is closed before
action authorization or replay reservation. Reconnecting remains limited for
the current window. The two counters advance atomically only when both admit,
so a global rejection does not consume a peer allowance. A structured bounded
retry response is future protocol work. The node never evicts live replay
records, skips authorization, expands file scope, or elevates privilege to
recover capacity.

## Offline operation

The local administrative endpoint and enabled local status functions do not
depend on Internet connectivity. A paired LAN peer may submit an action while
the central service is unreachable only if the node can validate all required
signatures and current local trust, policy, replay, and time state.

The node rejects new remote actions when paired credentials, revocation state,
trusted time, security storage, or policy cannot be verified. Cached DNS,
previous connectivity, or an existing socket is not evidence of current trust.

## Future private networks and relays

WireGuard, an owner VPN, or an explicit relay can carry the same transport in a
future deployment. They may change routing but not the application trust model:

- node and client mutual authentication remains end to end;
- exact-action owner and broker signatures remain mandatory;
- the relay receives no action authority;
- relay metadata and credentials are scoped and revocable;
- the node makes an explicit outbound relay connection if inbound reachability
  is required; and
- no provider-specific identity becomes the canonical NodeId or owner
  authority.

A relay that terminates encryption or can originate actions requires a new
threat model and is not part of this design.
