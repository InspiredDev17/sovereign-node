# Transitional Workload Admission

## Status

The `workload` module is a **development-only, unit-tested protocol
foundation**. It is not reachable from the v0.1 LAN action endpoint, does not
invoke a real service, and does not persist workload reservations. It must not
be described as production workload execution. Canonical types and fixtures in
Sovereign-AI-Contracts are the next external dependency.

Implemented in the module:

- deterministic, domain-separated Ed25519 `WorkloadIntentV1` signing;
- strict bounded postcard decoding with no trailing or noncanonical bytes;
- task, cognitive-plan, cognitive-node, correlation, control-plane, NodeId,
  trust-epoch, policy revision/digest, classification, locality, artifact,
  deadline and resource bindings;
- locally constructed trusted-service definitions; unknown IDs fail closed;
- explicit enrollment and Agent Green restrictive state;
- checked integer resource accounting and atomic in-process reservation;
- workload-ID and idempotency-key collision detection;
- typed state transitions and cancellation that retains resources until
  terminal reconciliation;
- signed, expiring node capability manifests and dynamic status types;
- a typed already-running-service adapter with bounded result validation; and
- deterministic Mac/Metal, Linux/CUDA and restricted CPU-only simulations that
  report eligibility without ranking nodes.

Not implemented in v0.1:

- canonical Sovereign-AI-Contracts wire types;
- a daemon workload listener or routing from AI-Avenger;
- a production-authenticated Native Inference Engine adapter;
- durable workload reservations, results or restart reconciliation;
- actual service invocation, cancellation or recovery;
- production-authenticated Agent Green restriction snapshots; or
- multi-host operation.

## Authority boundary

AI-Avenger decides the cognitive plan, specialist/model and cross-node
placement. Sovereign Node may only determine whether an already selected,
authenticated intent is eligible under local trust, policy, service, resource,
privacy and restriction facts. It never ranks models, rewrites the plan or
falls back to an external service.

Hardware capability is not model capability. Service availability is not
authorization. Node enrollment is not Action Broker authority. Agent Green may
only reduce effective authority. A service invocation is not arbitrary process
execution.

The effective decision is the intersection of control-plane authorization,
node policy and Agent Green restrictions. There is no union or best-effort
bypass.

## Locality

The implemented lattice has `PrivateNetwork` and the more restrictive
`ThisNodeOnly`. A node may satisfy a requirement only with an equal or more
restrictive locality. `SECRET` requires both intent and service to be
`ThisNodeOnly`; no external fallback, fetch, telemetry or remote substitution is
permitted.

## Admission order

The pure admission function validates, in order:

1. supported schema, protocol and contract revisions;
2. complete request structure and strict control-plane signature;
3. exact control-plane, NodeId and trust epoch;
4. exact local policy revision and digest;
5. ACTIVE enrollment, verified classification and healthy storage;
6. expiry/deadline and fresh resource state;
7. required/fresh Agent Green restrictions;
8. known, trusted, ready, compatible local service;
9. SECRET and general locality policy;
10. approved artifact identity; and
11. atomic resource/idempotency reservation.

Any failure returns a typed rejection and does not dispatch a service, create a
process, access the legacy action dispatcher or mutate the filesystem.

## State and recovery limit

Validated transitions cover Received, Validated, Admitted, Starting, Running,
Canceling, Recovering and terminal states. Terminal states cannot return to
Running. Cancellation moves to Canceling and retains capacity until explicit
terminal reconciliation.

The present ledger is memory-only. Daemon restart therefore cannot reconstruct
workload capacity or state, and the module is not suitable for consequential
production execution. Durable transactional reservation, result evidence,
service-status reconciliation and UNKNOWN_AFTER_CRASH handling must land after
the canonical contract is fixed.

The legacy action protocol remains separate through different types and
signature domains. Workload code cannot import or dispatch `FileRead`,
`FileWrite`, `ExecuteApprovedAction` or any Action Broker capability.
