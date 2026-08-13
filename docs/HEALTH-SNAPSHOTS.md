# Signed local health snapshots

Sovereign Node v0.1 can observe Agent Green and Action Broker health through
optional local snapshot files. This is a one-way reporting adapter. It cannot
start, stop, configure, update, enroll, or disable either component, and its
output is not host attestation.

The owner pins a separate Ed25519 public key and maximum age for each producer:

```toml
[health.agent_green]
snapshot_path = "/run/agentgreen/sovereign-node-health.json"
public_key_hex = "<64 lowercase or uppercase hexadecimal characters>"
max_age_secs = 60

[health.action_broker]
snapshot_path = "/run/sovereign-action-broker/health.json"
public_key_hex = "<a different 32-byte Ed25519 public key in hexadecimal>"
max_age_secs = 30
```

After configuring a producer, the owner may optionally add its matching
`AgentGreenHealth` or `ActionBrokerHealth` capability to
`policy.enabled_capabilities`. This is a policy change and requires a higher
`policy_version`. The capability only returns the same signed read-only health
observation; it grants no component control.

The outer snapshot file is strict JSON with exactly two hexadecimal fields:

```json
{
  "payload_hex": "<hex of the exact UTF-8 payload JSON bytes>",
  "signature_hex": "<128 hex characters containing an Ed25519 signature>"
}
```

After hexadecimal decoding, the payload is strict UTF-8 JSON:

```json
{
  "schema_version": 1,
  "component": "AgentGreen",
  "state": "Healthy",
  "observed_at_unix_ms": 1786579200000,
  "valid_until_unix_ms": 1786579260000,
  "detail_code": "contract-ok"
}
```

`component` is exactly `AgentGreen` or `ActionBroker`. `state` is exactly one
of `Healthy`, `Degraded`, `Unhealthy`, `Unavailable`, or `Unknown`.
`detail_code` is optional, 1 to 64 ASCII letters, digits, dots, dashes, or
underscores. It must not contain messages, paths, identifiers, credentials, or
other free-form data.

The producer signs this byte sequence with standard Ed25519:

```text
ASCII("sovereign-node/local-health-snapshot/v1\0") || exact_payload_json_bytes
```

The `\0` denotes one zero byte, not two printable characters. The producer then
hex-encodes the original payload bytes and the 64-byte signature into the
outer JSON. JSON property order and whitespace in the payload are not
canonicalized; the signature covers the exact payload bytes carried by
`payload_hex`.

The node reports `Unknown` with a generic reason when the adapter is absent or
when the file is missing, not regular, symlinked, larger than 8 KiB, malformed,
wrong-component, signed by the wrong key, observed in the future, expired, or
older/valid for longer than the configured maximum age. It never exposes the
snapshot path, signature, key, parser error, or raw payload in a remote result.

Snapshot producers should write a temporary file in the same directory, flush
it, and atomically rename it over the configured path. Private signing keys
remain with their producer and are never stored by Sovereign Node.
