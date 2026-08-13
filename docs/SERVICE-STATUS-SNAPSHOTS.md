# Signed local service-status snapshots

`ServiceStatus` is an optional read-only capability backed by a bounded local
file. Sovereign Node does not call a host service manager for remote callers.
An owner-operated producer maps local knowledge to stable logical identifiers,
signs a privacy-minimized snapshot, and atomically replaces the configured file.

```toml
[service_reporting.snapshot]
snapshot_path = "/run/sovereign-services/status.json"
public_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_age_secs = 30
```

The key must be valid non-weak Ed25519 and role-separated from process,
resource, health, release, and update-owner keys. The path must be absolute and
separate from other snapshot paths and remote file roots. Configuration may
advertise `ServiceStatus` only when this adapter exists. Adding or changing the
adapter selects the service-aware policy-digest schema and requires an
owner-controlled `policy_version` increment before the daemon serves. Removing
it restores the prior digest schema appropriate to the remaining adapters.

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
ASCII("sovereign-node/local-service-status-snapshot/v1\0") || exact_payload_json_bytes
```

The hexadecimal payload decodes to strict JSON:

```json
{
  "schema_version": 1,
  "observed_at_unix_ms": 2000000000000,
  "valid_until_unix_ms": 2000000030000,
  "services": [
    {
      "service_id": "model-engine.service",
      "state": "running",
      "detail_code": "ready"
    }
  ]
}
```

`service_id` and `detail_code` are bounded ASCII logical identifiers containing
only letters, digits, `.`, `_`, or `-`. Service IDs must be unique. `state` is
one of `running`, `starting`, `stopping`, `stopped`, `degraded`, `failed`, or
`unknown`. The snapshot contains 1 to 128 entries and the complete outer file
is at most 64 KiB.

## Fail-closed behavior

The node opens the final snapshot with no-follow semantics and requires a
regular bounded file, valid strict JSON and hex, the pinned strict Ed25519
signature, schema version 1, unique valid logical IDs, a non-future observation,
and a validity window and observation age no greater than `max_age_secs`.
Missing, stale, forged, malformed, oversized, symlinked, duplicate, or
wrong-key snapshots fail the capability without returning partial data. An
unknown exact logical target returns `TargetNotAllowed`.

## Privacy and authority boundary

Neither the snapshot schema nor the result has fields for unit-file or plist
paths, service-manager identifiers, executable paths, command lines,
environment, credentials, process IDs, users, dependencies, sockets, logs, or
configuration contents. Strict JSON rejects additional fields. This adapter
cannot enumerate, install, enable, disable, start, stop, restart, reload, or
otherwise control a service. It invokes no `systemctl`, `launchctl`, Windows
SCM, init script, or privileged helper. The producer key attests only to this
bounded local observation; it grants no remote action authority.
