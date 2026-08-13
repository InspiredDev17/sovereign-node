# Signed local process-status snapshots

`ProcessStatus` is an optional read-only capability backed by a bounded local
file. Sovereign Node does not inspect the host process table for remote callers.
An owner-operated producer maps local knowledge to stable logical identifiers,
signs a privacy-minimized snapshot, and atomically replaces the configured
file.

```toml
[process_reporting.snapshot]
snapshot_path = "/run/sovereign-processes/status.json"
public_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_age_secs = 30
```

The key must be valid non-weak Ed25519 and role-separated from resource, health,
release, and update-owner keys. The path must be absolute and separate from
other snapshot paths and remote file roots. Configuration may advertise
`ProcessStatus` only when this adapter exists.
Leaving the adapter absent preserves the previous policy-digest serialization.
Adding or changing it selects the versioned process-aware digest and requires
an owner-controlled `policy_version` increment before the daemon serves.

## Signed format

The outer file is strict JSON containing exactly:

```json
{
  "payload_hex": "...",
  "signature_hex": "..."
}
```

The signature covers:

```text
ASCII("sovereign-node/local-process-status-snapshot/v1\0") || exact_payload_json_bytes
```

The hexadecimal payload decodes to strict JSON:

```json
{
  "schema_version": 1,
  "observed_at_unix_ms": 2000000000000,
  "valid_until_unix_ms": 2000000030000,
  "processes": [
    {
      "process_id": "model-engine",
      "state": "running",
      "detail_code": "ready"
    }
  ]
}
```

`process_id` and `detail_code` are bounded ASCII logical identifiers containing
only letters, digits, `.`, `_`, or `-`. Process IDs must be unique. `state` is
one of `running`, `starting`, `stopping`, `stopped`, `degraded`, or `unknown`.
The snapshot contains 1 to 128 entries and the complete outer file is at most
64 KiB.

## Fail-closed behavior

The node opens the final snapshot with no-follow semantics and requires a
regular bounded file, valid strict JSON and hex, the pinned strict Ed25519
signature, schema version 1, unique valid logical IDs, a non-future observation,
and a validity window and observation age no greater than `max_age_secs`.
Missing, stale, forged, malformed, oversized, symlinked, duplicate, or
wrong-key snapshots fail the capability without returning partial data. An
unknown exact logical target returns `TargetNotAllowed`. A request for child
enumeration is a capability mismatch.

The appended `ManagedProcess` wire target is the only executable ProcessStatus
target. The older numeric `Process` target remains decodable for compatibility
but is always denied because a PID can be reused.

## Privacy and authority boundary

Neither the snapshot schema nor the result has fields for a numeric PID,
parent/child relations, executable or working-directory paths, command line,
environment, username, credentials, open files, sockets, memory contents, or
resource control. Strict JSON rejects additional fields. This adapter cannot
enumerate, signal, debug, start, stop, restart, or otherwise control a process.
The producer key attests only to this bounded local observation; it grants no
remote action authority.
