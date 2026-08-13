# Signed local repository-status snapshots

`RepositoryStatus` is an optional read-only capability backed by a bounded
local file. Sovereign Node does not open repository roots or invoke Git for a
remote caller. An owner-operated producer gathers local state independently,
maps repositories and branches to safe logical aliases, signs the minimized
snapshot, and atomically replaces the configured file.

```toml
[repository_reporting.snapshot]
snapshot_path = "/run/sovereign-repositories/status.json"
public_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_age_secs = 30
```

The key must be valid non-weak Ed25519 and role-separated from process,
service, resource, health, release, and update-owner keys. The path must be
absolute and separate from every other snapshot path and remote file root.
Configuration may advertise `RepositoryStatus` only when this adapter exists.
Adding or changing it selects policy-digest schema v4 and requires an
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
ASCII("sovereign-node/local-repository-status-snapshot/v1\0") || exact_payload_json_bytes
```

The hexadecimal payload decodes to strict JSON:

```json
{
  "schema_version": 1,
  "observed_at_unix_ms": 2000000000000,
  "valid_until_unix_ms": 2000000030000,
  "repositories": [
    {
      "repository_id": "primary",
      "status": {
        "head": "0123456789abcdef0123456789abcdef01234567",
        "branch": "main",
        "clean": false,
        "ahead": 1,
        "behind": 0,
        "untracked_count": 2
      }
    }
  ]
}
```

`repository_id` and `branch` are bounded logical aliases containing only
letters, digits, `.`, `_`, or `-`; they are not paths or remote-provided names.
Repository IDs must be unique. `head`, when present, is exactly 40 or 64
hexadecimal characters. Ahead, behind, and untracked counts are capped at one
million. A clean repository cannot have a positive known untracked count. The
snapshot contains 1 to 128 entries and the complete outer file is at most 64
KiB.

The action's signed `include_untracked_summary` argument controls whether the
bounded untracked count is returned. When false, the node removes that field
from the result even if the producer supplied it.

## Fail-closed behavior

The node opens the final snapshot with no-follow semantics and requires a
regular bounded file, valid strict JSON and hex, the pinned strict Ed25519
signature, schema version 1, unique valid logical IDs, valid bounded status, a
non-future observation, and a validity window and observation age no greater
than `max_age_secs`. Missing, stale, forged, malformed, oversized, symlinked,
duplicate, inconsistent, or wrong-key snapshots fail without partial data. An
unknown exact logical target returns `TargetNotAllowed`.

## Privacy and authority boundary

Neither the snapshot schema nor the result has fields for repository paths,
remote names or URLs, credentials, file names or contents, diffs, commit
messages or authors, tags, submodules, hooks, configuration, or logs. Strict
JSON rejects additional fields. The node does not enumerate directories, open
a work tree, invoke Git, fetch, switch branches, stage, commit, merge, rebase,
push, run hooks, or execute repository code. The producer key attests only to
this bounded local observation; it grants no remote action authority.
