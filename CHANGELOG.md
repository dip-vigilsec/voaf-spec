# Changelog

All notable changes to the VOAF specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-10-07

Minor. No preimage byte changes and the format tag stays `voaf-2.0`, so every
2.0.0 document and vector verifies unchanged.

### Added

- Two `gate_decision.decision` values, `shutdown_deny` and `connection_panicked`
  (`spec/2.0/preimage.md` section 4.7.1). Each records a held call that no person
  decided. In both, the held call was not delivered to the client.
  - `shutdown_deny`: the producer denied an open hold because it was shutting
    down, and wrote deny text in place of the call. Introduced in Vigil commit
    `ab2da26`, and extended to holds refused after shutdown began in `9aae674`.
  - `connection_panicked`: the task serving the connection failed while the hold
    was open, and the connection supervisor recorded the hold. Nothing of the held
    call was delivered. Introduced in Vigil commit `5fd9c39`.

  First written by Vigil 2.3.2. No tagged release before 2.3.2 writes either value.
- Section 7: a verifier MUST NOT count or present an unrecognised `decision` as an
  allow, and SHOULD report such records with the raw value. Raw means as stored;
  a verifier that shows a document string to a person escapes it first.
- Section 7.1: adding a `decision` value is a minor change. Removing one, or
  changing its meaning, is a major change.
- Six positive vectors, one for each `decision` value no earlier vector carried:
  `shutdown_deny`, `connection_panicked`, `timeout_deny`, `user_approve`,
  `always_allow` and `restore`. Two negative vectors: a NULL `decision`, and a
  `decision` edited without re-hashing. 24 vectors and 6 negative vectors in all.

### Changed

- Section 4.4: `connection_panicked`, like `client_disconnected`, carries a NULL
  `response_hash_delivered`, and it also carries a NULL `response_hash_upstream`.
  The rule is scoped to the held call: on a streamed response the events before
  it may already have reached the client.

### Fixed

- `spec/2.0/reference-verifier.rs` rejects a NULL `decision`, per section 7 rule 1.
  It used to encode the one-byte NULL marker, so the record verified. A missing
  `decision` already failed. Rule 1 covers every non-nullable field; the reference
  verifier checks `decision` only, and a NULL in another non-nullable field still
  encodes as the NULL marker.
- The reference verifier's unknown `event_kind` error escapes the kind in full,
  in both Display and Debug. It used Rust's `{:?}`, which escapes line breaks and
  controls but passes printable non-ASCII through, so a lookalike of a real kind,
  or an invisible filler character, reached any caller that printed the error.
  The escape writes `\u{..}` for everything outside printable ASCII, never `\n`,
  `\r` or `\t`, which a shell's `echo` turns back into line breaks.

### Compatibility

- A 2.0.0 verifier still verifies records carrying either new value, because
  section 7 rule 2 makes an unknown token not a failure. 2.0.0 did not say what a
  verifier may do with such a record. The section 7 addition does.

## [2.0.0] - 2026-09-02

Major. A 2.x verifier reads a 1.0 document in link-only mode and states that
content was not covered; it does not report such a document as simply verified.

### The reason for the major version

**VOAF 1.0 did not cover message content. VOAF 2.0 does.**

The 1.0 preimage was `SHA256(prev_hash || id || timestamp || features_json)`.
`user_message` and `ai_response` were not inputs. A 1.0 chain proves that a
record existed in a given order relative to its neighbours. It does not prove
what the record said, and anyone with write access to the store could rewrite
every captured prompt and response with the chain still verifying clean.

That is the gap 2.0 closes, and it is why this is 2.0 rather than 1.1: the
1.0 versioning policy classifies a change to the chain verification algorithm as
major, and this is that change.

### Added

- A length-prefixed byte preimage, not canonical JSON. One marker byte per field
  carrying its type, then a 4-byte big-endian length or count. `spec/2.0/preimage.md`.
- Message content, and a digest and byte length of the full content computed
  before any truncation, so a record remains verifiable against an original even
  when the text itself was not retained.
- Event kinds beyond `interaction`: `gate_decision`, `lifecycle`,
  `chain_upgrade`, `chain_truncation`. All share one chain in one `seq` order.
- An anchored genesis, `SHA256("vigil-genesis" || install_nonce)`, replacing the
  literal string `"genesis"` every install shared.
- `chain_upgrade` as record 0, committing by digest to the archived 1.0 document
  rather than migrating it. 1.0 records are retained and remain verifiable under
  1.0 rules.
- 18 test vectors and 4 negative vectors, `spec/2.0/test-vectors.json`. Five
  independent implementations reproduce them.
- A reference preimage implementation, `spec/2.0/reference-verifier.rs`.

### Changed

- The published 1.0.0 document format and the format Vigil actually shipped had
  diverged: this repository described `voaf: "1.0.0"` with a flat array,
  `content_hash` and an all-zeros genesis, while the shipped exporter emitted
  `voaf_version: "1.0"` with an object wrapper, `hash` and the literal
  `"genesis"`. That fork had been open since April 2026. 2.0 supersedes both, and
  the shipped exporter is the reference for it.

### Deliberately not included

- `transport` and `background` event kinds are named in Vigil's internal
  planning and have no field definition. Freezing a schema for them now would be
  inventing evidence semantics. They require a new tag when specified.

### What the format still does not claim

Stated here because the format exists for regulatory review and an overclaim is
the failure it is meant to prevent. Full list in section 9 of the preimage spec.

- **There is no trusted time.** `timestamp_us` is the recording device's own wall
  clock: unsynchronised, non-monotonic across a clock change, settable by anyone
  controlling the machine. The chain proves order, not time.
- **The chain is unkeyed and a document is unsigned.** An off-device verifier
  cannot distinguish a genuine export from a hand-written one.
- **Anchoring buys a narrow property.** A party who has never observed any record
  or export from an install cannot guess its genesis. The genesis appears in
  every exported document, so anyone who has seen one export can reproduce it.
- **Content is hashed as stored.** Where a producer truncates or declines to
  retain content, the record says so and carries the digest of the full original.

## [1.0.0] - 2026-03-17

### Added

- Initial VOAF v1.0.0 specification
- 8 required fields: `voaf`, `id`, `timestamp`, `provider`, `model`, `direction`, `content_hash`, `prev_hash`
- Gate decision fields: `gate_decision`, `gate_reason`, `gate_policy_id`, `gate_layer`
- Optional metadata: `session_id`, `user_id`, `device_id`, `content_body`, `token_count`, `latency_ms`, `tags`, `annotations`
- Semantic decomposition extension object
- SHA-256 append-only hash chain specification
- JSON Schema (`schema/voaf-v1.0.schema.json`)
- Example file with ALLOW, BLOCK, and FLAG entries
- Apache 2.0 license
