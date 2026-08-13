# Capability Model

## Deny-by-default contract

A capability is a compiled-in, typed operation enabled by an explicit local
policy. Advertising a capability reports what the node may consider; it does
not guarantee that a particular target or request is authorized.

Unknown capability names, unsupported versions, unconfigured targets, malformed
arguments, policy-version mismatches, and requests outside resource limits are
rejected. There is no general-command fallback.

The base daemon has no capability for a root shell, arbitrary shell, arbitrary
executable, arbitrary script, code upload, raw credential access, Agent Green
control, or automatic update.

## v0.1 implementation status

The hardened v0.1 default manifest permits only `SystemInfo` and
`ResourceStatus`. When its corresponding component-specific signed local
adapter is configured, the owner may explicitly add `GpuStatus`,
`EngineStatus`, `ModelStatus`, `ProcessStatus`, `AgentGreenHealth`, or
`ActionBrokerHealth` and increment `policy_version`. Configuration validation
rejects those capabilities without their exact adapter and rejects advertising
every other capability below. In particular, `FileRead`, `FileWrite`, and
`ExecuteApprovedAction`
remain unavailable until
descriptor-relative no-follow access, credential exclusions, atomic writes,
and a separate OS sandbox/process boundary are implemented and tested.
Unverifiable process snapshots fail the specific request; unverifiable GPU,
engine, model, Agent Green, and Action Broker measurements report `Unknown`/no
verified entries rather than inventing state.

## Manifest

The device-signed capability manifest includes:

- NodeId, trust generation, policy version, and manifest digest;
- capability name and schema version;
- argument and result schema digests;
- owner-readable target-scope summary;
- required operating-system privileges;
- per-request input, output, time, and concurrency limits;
- whether the capability is read-only or may change state;
- availability state and reason code; and
- short issuance and expiration times.

The manifest omits secret paths, credentials, private hardware identifiers, and
details that would materially aid reconnaissance. A remote party cannot modify
the manifest. A local policy change is atomic, versioned, and audited.

## Common authorization checks

Before any executor receives arguments, the runtime verifies:

- mutually authenticated paired transport;
- supported protocol, capability, argument, and result versions;
- exact destination NodeId and active trust generation;
- owner and Action Broker signatures over the exact action envelope;
- UserAuthority scope for the capability and target;
- arguments digest after local canonicalization;
- expiration and trustworthy local time;
- RequestId replay reservation;
- local capability, target, and policy-version match; and
- global and per-capability resource limits.

Capability-specific validation can narrow authority but can never widen it.

## Capability definitions

### SystemInfo

Read-only, privacy-minimized operating-system and architecture information,
Sovereign Node software version, supported protocol versions, and broad
hardware capability classes.

It does not return usernames, environment variables, serial numbers, MAC
addresses, firmware identifiers, installed credential locations, or arbitrary
package inventories.

### ResourceStatus

Read-only bounded measurements for:

- CPU utilization and logical capacity;
- one-minute system load when the operating system exposes it;
- used, available, and total RAM;
- used, available, and total disk for explicitly configured volumes;
- GPU utilization when supported;
- VRAM or unified-memory usage when supported;
- thermal state when supported;
- bounded queue depth and configured capacity; and
- sampling time and freshness.

Unsupported and stale measurements are Unknown. The executor applies sampling
deadlines and does not invoke unbounded vendor utilities.

GPU, unified-memory, thermal, inference-engine, and loaded-model measurements
may be supplied through the optional signed local resource snapshot described
in [RESOURCE-SNAPSHOTS.md](RESOURCE-SNAPSHOTS.md). The node verifies the exact
payload, freshness window, role-specific key, unique logical identifiers,
memory bounds, temperatures, and protocol collection limits before accepting
the snapshot. A failure rejects the entire optional snapshot and returns only
the safe unknown/empty representation. Empty GPU or model lists mean no
verified entries, not verified absence.

### FileRead

Reads only within owner-configured roots and only when the action authority
names an allowed logical target. Policy defines maximum bytes, permitted file
types where useful, and whether metadata or content is allowed.

The executor:

- canonicalizes the logical target without trusting string prefixes;
- performs descriptor-relative, no-follow path traversal where supported;
- rejects absolute paths, parent traversal, symlinks, hard-link escapes where
  detectable, devices, sockets, pipes, and credential-policy exclusions;
- verifies the opened object remains beneath the allowed root;
- limits bytes and time; and
- never reads the node identity store, audit store, replay store, private keys,
  raw credentials, or Agent Green secrets.

If the platform cannot enforce the configured boundary safely, FileRead is
unavailable rather than weakened.

### FileWrite

Writes only to separately configured writable roots. Read permission does not
imply write permission. Policy fixes maximum input size, file mode, overwrite
behavior, and allowed target types.

The executor applies the FileRead path protections, refuses executable or
credential targets by default, writes a temporary file inside the authorized
directory, synchronizes it as policy requires, and atomically renames it after
all checks. It does not change ownership, grant execute permission, follow
links, write devices, or unpack archives. The audit stores a content digest and
byte count, not file content.

### ProcessStatus

v0.1 optionally returns bounded status for an exact owner-defined logical
process identifier through the signed local snapshot contract in
`PROCESS-STATUS-SNAPSHOTS.md`. Enabling it requires a pinned, role-separated
producer key and fresh no-follow snapshot. The result contains only the logical
ID, a small state vocabulary, snapshot observation time, and an optional
sanitized detail code.

It does not enumerate every process, expose command lines or environments,
attach a debugger, send signals, or start and stop processes.
The legacy numeric-PID wire target is never executable: PIDs are reusable and
therefore cannot serve as stable authorization identities. Requests also cannot
ask for child-process enumeration.

### ServiceStatus

Queries a configured allowlist of service names through a read-only
platform-specific adapter. Results use a small state vocabulary plus timestamp
and reason code. It does not return unit files, environment values, credentials,
or an unrestricted service-manager interface.

Starting, stopping, enabling, disabling, or editing a service is outside this
capability.

### ExecuteApprovedAction

Invokes one owner-installed action definition by stable action ID. Each
definition fixes:

- an absolute, owner-controlled executable path;
- executable file digest or signed-package identity when supported;
- a typed argument schema and allowlisted values;
- fixed working directory and sanitized environment;
- unprivileged operating-system account;
- filesystem and network scope;
- timeout, output limit, and concurrency;
- expected exit and result mapping; and
- whether the action is idempotent and how crash recovery is reconciled.

The request cannot supply an executable path, shell command, interpreter flag,
script body, environment variable, working directory, redirection, or uploaded
binary. The runtime invokes the executable directly without a shell. A changed
binary digest disables the action until the owner approves a new local policy
version.

### GPUStatus

Returns bounded verified GPU indexes, utilization, memory kind, memory totals
and use, and temperature when supported. An optional target selects one GPU by
its local numeric index; a missing exact index is denied. Snapshot freshness is
enforced locally before the result is returned.

Serial numbers, PCI topology, device UUIDs, and vendor account data are omitted
unless the owner has a narrow local reason to expose them. Producer failure
returns no verified GPU entries, not a fabricated zero or Healthy state.

### EngineStatus

Reports configured native inference-engine availability and compatible runtime
version. An optional target selects one engine by its owner-safe logical ID; a
missing exact ID is denied. Snapshot freshness is enforced locally.
It does not submit inference work, download an engine, alter engine settings, or
return engine credentials.

### ModelStatus

Reports only verified loaded/loading/unloading/failed model aliases, engine
association, and optional allocated memory. An optional target selects one
model by its owner-safe logical ID; a missing exact ID is denied. It
does not return model weights, secret filesystem paths, license credentials, or
provider tokens. Loading, unloading, downloading, and deleting models require
separate future capabilities and are not implied.

### RepositoryStatus

Reports bounded, read-only status for explicitly configured repository roots:
logical alias, current revision, branch when available, clean or dirty state,
ahead or behind state when already known locally, and timestamp.

It does not enumerate arbitrary directories, read diffs or file content, expose
remote credentials or URLs containing secrets, fetch a network remote, switch
branches, commit, push, run hooks, or execute repository code.

## Health reporting

Resource reports include Action Broker and Agent Green health only through
configured local health adapters. Each health value is:

- Healthy: a fresh, authenticated local health contract succeeded;
- Unhealthy: a fresh health contract reported a defined failure; or
- Unknown: unsupported, stale, unreachable, unauthenticated, malformed, or
  otherwise unverifiable.

The v0.1 adapter reads a bounded local file without following the final
symlink, verifies a component-specific pinned Ed25519 key over the exact JSON
payload bytes, enforces the producer's observation and expiration times, and
accepts only a bounded machine-readable detail code. Agent Green and Action
Broker keys must be distinct. See [HEALTH-SNAPSHOTS.md](HEALTH-SNAPSHOTS.md)
for the producer contract.

Agent Green is an independent security monitor. Sovereign Node may observe its
health but cannot start, stop, disable, configure, update, or claim to replace
it. Process presence by itself never yields Healthy.

## Queue and load behavior

The runtime exposes bounded queue depth, active count, configured capacity, and
oldest-work age without request contents. Admission control occurs after cheap
framing checks and before expensive work where possible.

When capacity is exhausted:

- the node rejects new work with a stable reason code;
- no action bypasses authorization or jumps an authority boundary;
- replay reservations are preserved;
- completed results remain bounded;
- status capability capacity is reserved where practical; and
- recovery does not kill or disable Agent Green.

## Results and audit

Every result is associated with RequestId and has a terminal state such as
Succeeded, Denied, Failed, TimedOut, CancelledBeforeExecution, or Indeterminate.
Results are bounded and redacted. A capability never returns private keys,
tokens, full environment variables, credential files, or raw authorization
signatures.

The audit journal records request, task, agent, authority, node, capability,
logical target, argument digest, policy version, decision, timing, and result
digest. Sensitive arguments and file contents are not audit payloads.

## Adding a capability

A new capability requires:

1. a documented typed request and result schema;
2. a local target and privilege policy;
3. threat analysis for filesystem, process, network, and secret exposure;
4. deterministic authorization and replay behavior;
5. strict resource limits and redaction rules;
6. tests for denial, boundary escape, restart, and exhaustion;
7. an owner-approved policy and manifest version change; and
8. evidence that it does not create an arbitrary execution primitive.

Capabilities are not remotely installed or generated by AI.
