# Changelog

All notable changes to the VOAF specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-10-08

Minor. No preimage byte and no hash changes, and the format tag stays
`voaf-2.0`. Every 2.0.0 vector, the chain, and every document that carries only
what section 4 declares verify unchanged.

### Security

- **A 2.0.0 verifier accepts documents that carry text no hash covers. 2.1.0
  forbids them, and no hash changes.** Under 2.0.0 a record could carry, and the
  2.0.0 reference verifier verified:
  - a member no section 4 table declares, which no preimage reads;
  - a second member with the same name, of which a parser keeps one and the hash
    covers only that one;
  - the vectors-file `$repeat` directive, which the verifier expanded in any
    record, so anything written beside it or inside it was dropped before
    hashing.

  In each case the record read as verified while carrying text outside every
  hash. The section 2 encoding is unambiguous over decoded values, so every one
  of these lives in the step from JSON to values, and 2.1.0 closes them there:
  the document is parsed with no repeated member name (RFC 7493 section 2.3), a
  record's members are exactly `seq`, `prev_hash`, `id`, `timestamp_us`,
  `event_kind`, `hash` and its kind's fields, and an object or array where a
  scalar is declared does not decode (`spec/2.0/preimage.md` sections 4.2.1 and
  7). One negative vector shows each case accepted by the 2.0.0 reference
  verifier and rejected by this one.

### Added

- Two `gate_decision.decision` values, `shutdown_deny` and `connection_panicked`
  (section 4.7.1). Each records a held call that no person decided. In both, the
  held call was not delivered to the client.
  - `shutdown_deny`: the producer denied a hold because it was shutting down,
    and wrote deny text in place of the call. Introduced in Vigil commit
    `ab2da26`, and extended to holds refused after shutdown began in `9aae674`.
  - `connection_panicked`: the task serving the connection panicked while the
    hold was open, and the connection supervisor recorded the hold. Nothing of
    the held call was delivered. Introduced in Vigil commit `5fd9c39`.

  First written by Vigil 2.3.2, which is the source at Vigil commit `c449787` and
  is not tagged at the time of writing. No tagged release writes either value.
- Section 4.4.1: what every (`verdict`, `decision`) pair records, ten in all:
  who decided, who recorded it, whether the call was delivered and what was
  written in its place, with (`hold`, `allow`), observe-only, and (`allow`,
  `restore`), not a tool-call decision, spelled out, and what the response hash
  fields cover. "An allow" is defined: the four pairs that say the call was
  delivered.
- Section 7: the parse check, and rule 1 as a list of its checks.
- Section 7 rule 2: a verifier MUST NOT count or present an unrecognised
  `decision` as an allow, and SHOULD report such records with the raw value. Raw
  means as stored; a verifier that shows a document string to a person escapes
  it first.
- Section 7.1: adding a `decision` value is a minor change, and adds its row to
  section 4.4.1. Removing one, or changing its meaning, is a major change.
- Six positive vectors, one for each `decision` value no earlier vector carried:
  `shutdown_deny`, `connection_panicked`, `timeout_deny`, `user_approve`,
  `always_allow` and `restore`.
- Eight negative vectors: a NULL `decision`, a `decision` edited without
  re-hashing, and one for each check rule 1 and the parse check gain:
  `neg_repeat_in_document`, `neg_unknown_member`, `neg_duplicate_member`,
  `neg_verdict_null`, `neg_rule_id_null` and `neg_features_canonical_null`. Each
  names the `violation` it must produce. 24 positive and 12 negative vectors in
  all.
- `verifier/`: builds `spec/2.0/reference-verifier.rs` as a library and runs
  every vector against it, with the vector, negative and chain counts pinned. CI
  runs it on every pull request and every push to `main`, and checks that every
  test ran.

### Changed

- Section 4.2.1: the `$repeat` directive belongs to the vectors file. A loader
  expands it in `vectors[].record` only; a document never carries it, and a
  verifier never expands it.
- Section 4.4: the NULL-delivery rule is scoped to the held call, and a present
  `response_hash_delivered` is what the producer wrote or was writing, not
  evidence of receipt. In Vigil 2.3.2 `client_disconnected` is written only on a
  streamed response, when a keepalive write fails, and a buffered hold record is
  written before the body is forwarded.
- Section 4.7.1: the shutdown drain is not atomic in Vigil 2.3.2. A hold
  inserted as the drain runs is never recorded as `shutdown_deny`, and most often
  has no record at all.
- Section 7 rule 2: an `event_kind` is the stated exception to "an unknown token
  is not a failure", because it selects the field table. It already was in
  practice; the text contradicted itself.
- Section 5.1: the re-root is the pattern for every future format tag, not every
  major version, matching section 7.1.
- Citations: the header names the files in this repository, says Vigil carries
  a copy of the vectors, and says the document format is not published. Paths
  that exist only in Vigil say so.
- Section 8.1 documents every field of the vectors file.

### Fixed

- `spec/2.0/reference-verifier.rs`:
  - Enforces section 7 rule 1 for every field from the Nullable column of the
    section 4 tables, and for every array element. The 2.0.0 file encoded a NULL
    anywhere as the NULL marker, so a NULL `decision`, `verdict`, array element
    or `features_canonical` verified.
  - Rejects a member outside the record's fields, and an object or array where a
    scalar is declared. `preimage()` expands nothing. `expand_vector_record()` is
    the vectors-file loader, and the only place the directive is expanded.
  - `parse_document()` parses a document and rejects a repeated member name.
  - Clamps the `$repeat` count before allocating, as Vigil's vigil-verify has
    since `204a776`. A count of 2^63 or more panicked, and a large one allocated
    its size before the field limit was checked.
  - `content_covered` counts content that is present and non-null, as
    vigil-verify has since `dfba3ad`. Content stripped to nulls read as covered.
  - The unknown `event_kind` error escapes the kind in full, in both Display and
    Debug. It used Rust's `{:?}`, which passes printable non-ASCII through, so a
    lookalike of a real kind, or an invisible filler character, reached any
    caller that printed the error. The escape writes `\u{..}` for everything
    outside printable ASCII, never `\n`, `\r` or `\t`, which a shell's `echo`
    turns back into line breaks.
  - Its header says what it is: independent of the writer, and kept in step
    with vigil-verify, of which it began as a copy.
- `neg_field_count_mutated` changes the count from 35 to 32, not from 33.

### Compatibility

- A 2.0.0 verifier still verifies records carrying either new value, because
  section 7 rule 2 makes an unknown token not a failure. 2.0.0 did not say what a
  verifier may do with such a record. The section 7 addition does.
- A document 2.1.0 rejects and 2.0.0 accepted carries an undeclared member, a
  repeated member name, the `$repeat` directive or a NULL the section 4 tables
  forbid. Section 2.2 already made any field outside a kind's list a new tag,
  section 4.2.1 already confined the directive to the vectors file, and rule 1
  already made a nullability violation a failure; 2.1.0 makes each check
  explicit and the reference verifier enforces it. Vigil's exporter writes none
  of them.
- The reference verifier's interface changed: `schema()` returns the Nullable
  column as a third element, `preimage()` no longer expands `$repeat`, and a
  caller loading the vectors file expands with `expand_vector_record()`.

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
