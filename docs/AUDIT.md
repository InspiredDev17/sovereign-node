# Local Audit Export

Sovereign Node keeps authorization, replay, lifecycle, and terminal-result
evidence in an owner-only SQLite journal. `sovereign-node audit export` is a
local read-only command for taking a bounded, redacted snapshot of that
journal. It is not a remote capability, listener, relay, upload, or monitoring
control channel.

## Command

```text
sovereign-node audit export \
  --config /absolute/path/to/sovereign-node.toml \
  --after-sequence 0 \
  --limit 100
```

The command writes one JSON document to standard output. It does not create a
file or transmit the document. The operator chooses any destination and must
protect exported evidence according to local policy.

`limit` must be between 1 and 1000. `after-sequence` is exclusive. The response
contains `has_more`, the full verified chain count and tail hash, and the hash
immediately before the page. Continue with the last returned event sequence.
An offset beyond the current tail is rejected rather than treated as an empty
successful page.

## Offline verification

Verify a page only against identity and chain values retained separately by the
owner. Do not copy the expected values out of the untrusted export itself.

```text
sovereign-node audit verify \
  --input /absolute/path/to/audit-page.json \
  --expected-node-id 11111111-1111-4111-8111-111111111111 \
  --expected-node-key-id-sha256 1111111111111111111111111111111111111111111111111111111111111111 \
  --expected-after-sequence 0 \
  --expected-anchor-sha256 0000000000000000000000000000000000000000000000000000000000000000
```

The NodeId and device-key ID must come from a previously authenticated pairing,
registration, or owner-retained identity-rotation record. For the genesis page,
the cursor is zero and the anchor is 64 hexadecimal zeroes. For every later
page, use `continuation_after_sequence` and `continuation_anchor_sha256` from
the prior verified receipt. The receipt provides continuation values even when
`has_more` is false, allowing a later poll to verify events appended afterward.

The verifier accepts only a no-follow regular file of at most 32 MiB. It uses
strict JSON decoding, verifies the signed canonical structure, then compares
the signed NodeId, key ID, cursor, and anchor with all four owner-supplied pins.
On success it prints a concise receipt; on any mismatch it exits without a
successful receipt. It opens no node configuration or state database, contacts
no network, and mutates nothing.

## Signature and chain checks

Before signing a page, the node:

1. reads the page, action contexts, and chain tail from one coherent SQLite
   snapshot, then verifies every stored audit-event hash and the complete local
   hash chain;
2. verifies the selected page's sequence and previous-hash links;
3. validates every included action-context digest;
4. checks RequestReserved and ExecutionStarted context links when those events
   are in the page;
5. binds the page cursor, limit, chain count, tail, events, and contexts into a
   deterministic postcard payload under the domain
   `sovereign-node/local-audit-export/v1`; and
6. signs that payload with the node device Ed25519 key.

The JSON includes the corresponding node public key and key ID. The library's
`SignedAuditExportV1::verify` method and the pinned `audit verify` CLI reject
weak or mismatched keys, malformed pages, broken event hashes or links,
inconsistent or non-progressing pagination, modified action contexts, and
noncanonical or forged signatures. Established Ed25519 and SHA-256
implementations are used; the project defines no custom cryptography.

The embedded key proves which device key signed the page. An owner correlates
that key with the NodeId and any separately retained identity-rotation bindings.
An export is not host attestation and does not prove that a root-compromised
machine was honest when it produced the page.

For a non-final page, the node signature binds the declared full-chain count
and tail, but an offline verifier cannot independently re-hash events that are
not present in that page. Verifying every page in order against the prior
receipt establishes continuity for the events actually received.

## Redaction boundary

An export may contain:

- RequestId, TaskId, event IDs, sequence numbers, and timestamps;
- event kind and outcome;
- capability name;
- policy version;
- hashes of agents, owner authorities, nodes, pairings, targets, arguments,
  authorizations, policies, results, and error categories; and
- bounded terminal metadata and action-lifecycle timestamps.

It structurally excludes raw agents and owner IDs, peer labels, logical target
values, arguments, approval reasons, file contents, response bodies,
signatures from remote authorizations, credentials, private keys, environment
variables, process command lines, repository content, and Agent Green secrets.

Historical replay entries created before state schema v9 have no fabricated
action context. Their original hash-chained events and terminal evidence remain
exportable.

## Limitations

The local journal and exported page provide origin, correlation, and
modification evidence within the node's trust assumptions. They are not
tamper-proof against an attacker who controls root, steals the device key, and
rewrites all local state. Timely export to owner-controlled storage improves
survivability but grants no control back to the Personal AI Platform.

Audit export never starts, stops, configures, or disables Agent Green. Agent
Green remains independently operated and may consume exported evidence only
through a separately authorized, read-only integration.
