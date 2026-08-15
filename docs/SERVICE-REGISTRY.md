# Transitional Trusted Service Registry

## Implemented development boundary

`workload::TrustedServiceRegistry` accepts only local typed definitions supplied
by trusted node configuration code. Definitions bind a bounded canonical
service ID, protocol and accepted contract revisions, pinned endpoint identity
digest, service version, trust/health/locality, execution classes, approved
artifact digests, truthful sandbox enforcement fields and a bounded
availability reason.

Duplicate, malformed, oversized and unknown services fail closed. Workload
requests cannot create a definition, choose an endpoint path, executable,
network target, environment or filesystem root.

`SovereignServiceAdapter` is the smallest transitional interface for health,
typed execution, cancellation and reconciliation against an already-running
service chosen by the registry. It has no process API. There is no production
adapter or daemon wiring in v0.1; tests use deterministic in-memory behavior.

## Service ownership

This repository does not currently supervise services. Native Inference Engine,
Action Broker, Memory Vault and Agent Green remain separately operated. Node may
eventually authenticate their pinned endpoints and report health,
compatibility, readiness and resource eligibility. It may not duplicate their
internal authority.

If Node later owns supervision, that must be a separate reviewed subsystem with
local-only immutable definitions, descriptor-pinned executable identity,
dedicated credentials, bounded environment/output, process-group ownership,
descendant termination, restart limits and platform-specific sandbox evidence.
It cannot reactivate `ExecuteApprovedAction` or accept process details from a
workload.

## External dependency

Sovereign-AI-Contracts must define canonical service identity, endpoint
authentication, health/readiness, workload, cancellation, reconciliation and
result envelopes before the transitional local types become a stable wire
contract.
