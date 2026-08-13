# Signed local resource snapshots

Sovereign Node v0.1 can accept optional accelerator and inference measurements
from a local producer. This is a one-way, read-only reporting contract. The
node never invokes vendor utilities, downloads a model, starts an engine, or
grants the producer action authority.

The owner configures a dedicated Ed25519 producer key and freshness limit:

```toml
[resource_reporting.snapshot]
snapshot_path = "/run/sovereign-resources/snapshot.json"
public_key_hex = "<32-byte Ed25519 public key in hexadecimal>"
max_age_secs = 30
```

This key and path must be distinct from Agent Green and Action Broker health
producers. The key must also be distinct from update release and owner-approval
keys. Changing the producer, path, or freshness policy requires a higher node
`policy_version`.

After configuring this adapter, the owner may optionally add `GpuStatus`,
`EngineStatus`, and `ModelStatus` to `policy.enabled_capabilities`. The aggregate
forms return every verified bounded entry. A request may instead name one GPU
index or one logical engine/model ID; an exact target that is not present in a
fresh verified snapshot is denied rather than returned as an empty success.

## Envelope and signature

The snapshot file is strict JSON:

```json
{
  "payload_hex": "<hex of exact UTF-8 payload JSON bytes>",
  "signature_hex": "<128 hex characters containing an Ed25519 signature>"
}
```

The producer signs:

```text
ASCII("sovereign-node/local-resource-snapshot/v1\0") || exact_payload_json_bytes
```

The `\0` denotes one zero byte. JSON is not canonicalized: `payload_hex` carries
the exact bytes covered by the standard Ed25519 signature.

## Payload

The decoded payload is strict JSON. This abbreviated example uses the exact
Rust/Serde enum names accepted by v1:

```json
{
  "schema_version": 1,
  "observed_at_unix_ms": 1786579200000,
  "valid_until_unix_ms": 1786579230000,
  "unified_memory": {
    "total_bytes": 34359738368,
    "available_bytes": 21474836480,
    "used_bytes": 12884901888
  },
  "gpus": [
    {
      "index": 0,
      "utilization": 420,
      "memory_kind": "Unified",
      "total_memory_bytes": 34359738368,
      "used_memory_bytes": 8589934592,
      "temperature_millidegrees_celsius": null
    }
  ],
  "thermal_state": "Nominal",
  "inference_engines": [
    {
      "engine_id": "native-engine",
      "native": true,
      "availability": "Available",
      "version": "1.2.3"
    }
  ],
  "loaded_models": [
    {
      "model_id": "owner-model-1",
      "engine_id": "native-engine",
      "state": "Loaded",
      "allocated_memory_bytes": 8589934592
    }
  ]
}
```

Utilization is permille from 0 through 1000. Temperature is optional
millidegrees Celsius. Memory values are bytes. Logical engine and model IDs are
1 to 256 ASCII letters, digits, dots, dashes, or underscores; they are not
paths, model prompts, repository names, raw hardware identifiers, or secret
provider IDs. At least one engine entry must be marked `native: true` so native
inference availability is explicit.

The node rejects the entire optional snapshot when it is missing, not regular,
symlinked, larger than 256 KiB, malformed, forged, future-dated, expired, valid
for longer than the configured maximum age, over protocol collection limits,
or internally inconsistent. It also rejects duplicate GPU, engine, or model
IDs; impossible memory totals; out-of-range utilization or temperatures;
unknown model-to-engine references; and unified-memory totals larger than host
RAM. A `Loaded` model must reference an `Available` or `Degraded` engine, and
its allocation cannot exceed host RAM plus reported dedicated VRAM. The
fallback is `Unknown` thermal/native-engine availability, no asserted
unified memory, and empty GPU/model lists. Those empty lists do not prove
hardware or models are absent.

When a snapshot is accepted, the combined `ResourceStatus.observed_at` is set
to the snapshot's observation time. CPU, RAM, disk, and queue values are sampled
at request time, so this conservative timestamp never makes the older optional
accelerator/model measurements appear fresher than they are.

The producer should write a temporary file in the same directory, flush it,
and atomically rename it over the configured path. Its private key remains with
the producer and is never stored by Sovereign Node.
