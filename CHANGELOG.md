# Changelog

All notable changes to the VOAF specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-10-08

Minor. No preimage byte and no hash changes, and the format tag stays `voaf-2.0`.

**Compatibility, stated once:** the documents 2.1.0 newly fails are malformed
under I-JSON (a repeated member name, RFC 7493 section 2.3), have records that
carry members or content no record hash covers, or break a rule 2.0.0 already
stated: the section 4 nullability column, a declared field being present
(2.0.0's rule 1 failed a field that does not decode, and its reference verifier
rejected a missing one but not a NULL in a body field), the 1.0 schema, `seq`
being unique and gapless, and the anchor's definition. One exception: 2.1.0
states the four document members a verifier reads, which 2.0.0 left to an
unpublished format, and rejects a document without `records` or `genesis`, with
either of the wrong type, or without a declared version it recognises. Vigil
2.3.2's export of a store with no records and no genesis is such a document;
2.0.0 reported it `empty`. Members outside the records stay outside every hash,
and a top-level member a verifier does not read is ignored. Every document a 2.0
producer actually emitted with records still verifies, and every 2.0.0 vector
and the chain reproduce unchanged. Known producer deviation: Vigil 2.3.0 and
2.3.1 record producer denials as `user_deny`, so a `user_deny` from those
releases does not prove a person decided (appendix A.4). One passage of 2.0.0
described `client_disconnected` more broadly than any producer wrote it; it is
corrected as an erratum, below. Section 7.1 states the rule that makes such a
release minor.


### Security

- **A 2.0.0 verifier accepts records that carry text no hash covers. 2.1.0
  forbids them inside records, and no hash changes.** Under 2.0.0 a record could
  carry, and the 2.0.0 reference verifier accepted:
  - a member no section 4 table declares, which no preimage reads;
  - a second member with the same name, of which a parser keeps one and the hash
    covers only that one;
  - the vectors-file `$repeat` directive, which the verifier expanded in any
    record, so anything written beside it or inside it was dropped before
    hashing.

  In each case the record read as verified while carrying text outside every
  hash. 2.0.0 also never said what type the stored hash has, so a `hash` member
  could be an object carrying other text; a verifier that compared it as a string
  rejected that, and 2.1.0 makes `hash` a present string. The section 2 encoding is unambiguous over decoded values, so each of
  these lives in the step from JSON to values, and 2.1.0 closes them there
  (`spec/2.0/preimage.md` sections 4.2.1 and 7).
- **Members outside the records stay outside every hash.** The declared format,
  the genesis, the anchor and any exporter metadata are covered by no record
  hash, in 2.0.0 and in 2.1.0 (section 9). The declared version decides how a
  document is walked. A 1.0 verdict never asserts content integrity, and a
  verifier cannot always detect a relabelled 2.x document; what it can detect, a
  document that declares 1.x and carries 2.x-only structure, it rejects
  (section 7). Under 2.0.0 such a document, a 2.0 chain relabelled 1.0 with a
  record altered, passed a link-only walk; Vigil's own 2.0 verifier reported it
  verified. The genesis and anchor a document carries are self-asserted: section
  7 checks the records against them, which catches a document inconsistent with
  itself, not one rewritten whole.

### Erratum

- Section 4.4 of 2.0.0 said the `client_disconnected` outcome is exactly the case
  of "a hold whose client left mid-hold", which "delivered no bytes". Both were
  broader than any producer wrote it: a producer records `client_disconnected`
  only when it finds the client gone, and on a streamed response the events
  before the held call may already have been delivered. 2.1.0 corrects the text.
  The value's meaning, that nothing was delivered for the held call, is
  unchanged, and no producer wrote a record the corrected text does not describe.

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
- Section 7: the parse check; the 2.x-structure check on a 1.x declaration, with
  the 1.0 verdict as the protection when a relabelled document cannot be
  detected; a 1.0 verdict that never asserts content integrity and never matches
  a 2.x verdict; rule 1 as a list of its checks; a code for every check, rule 4's
  `link_break` included; and a MUST to escape every document string a verifier
  shows a person.
- Section 7, on a document as a whole:
  - the four top-level members a verifier reads in a 2.x document,
    `voaf_version`, `records`, `genesis` and `anchor`; every other top-level
    member is ignored;
  - which declared versions are 1.x and which 2.x;
  - records walked in `seq` order, whatever the array order;
  - the chain checks, each with a code. A duplicate `seq` is `broken`. A `seq`
    gap whose links hold is `truncated`, and so is record 0 missing, not a
    `chain_upgrade`, or not linked to the genesis;
  - the carried anchor checked against the records, with an unanchored tail, or
    a tail whose truncation cannot be detected, reported;
  - a code and a verdict for every check, in one table, and the precedence
    `broken`, then `truncated`.
- Section 7 rule 2: a verifier MUST NOT count or present a record whose
  (`verdict`, `decision`) pair it does not recognise as an allow, whether a value
  is unknown or the pair is not one section 4.4.1 lists, and SHOULD report such
  records with the raw values.
- Section 7.1: adding a row to section 4.4.1, a new value or a new pair, is a
  minor change; removing a row or changing its meaning is a major change. It
  also says when a stricter release is minor.
- Appendix A, known producer deviations, and appendix B, producer notes, both
  non-normative: where Vigil 2.3.2 does not meet the section 4 definitions,
  including the shutdown drain race, allow pairs for calls never released, every
  loss path found for holds and calls that leave no record, and Vigil 2.3.0 and
  2.3.1 recording producer denials as `user_deny`; and how Vigil 2.3.2 writes the
  records that meet the definitions.
- Six positive vectors, one for each `decision` value no earlier vector carried:
  `shutdown_deny`, `connection_panicked`, `timeout_deny`, `user_approve`,
  `always_allow` and `restore`.
- Eighteen negative vectors, each naming the `violation` it must produce: a NULL
  `decision`; a `decision` edited without re-hashing; the parse check twice
  (`neg_duplicate_member`, last copy kept, and `neg_duplicate_member_mirror`,
  first copy kept); one for each rule 1 check the v2.0.0 reference verifier did
  not make (`neg_repeat_in_document`, `neg_unknown_member`,
  `neg_hash_not_a_string`, `neg_verdict_null`, `neg_held_ms_null`,
  `neg_is_anomaly_null`, `neg_rule_id_null`, `neg_feature_element_null` and
  `neg_features_canonical_null`); three for rule 1 checks that verifier made
  but a reader without them would pass (`neg_field_over_limit`,
  `neg_held_ms_string` and `neg_id_null`); `neg_nullable_field_absent`, which
  that verifier already rejected; and `neg_relabelled_1_0`, a whole document.
  Every record-form negative carries its stored hash as `hash`.
  `neg_field_over_limit` carries its 1,048,577-byte value literally, so the file
  is now about 1.2 MB.
- Nine negative documents, `negative_documents`, each naming its verdict and
  codes: a middle record deleted, a `seq` gap re-linked, record 0 not a
  `chain_upgrade`, an anchor counting more records than the document holds, an
  anchor head that does not match, a duplicate `seq`, two `records` members, and
  a document without `voaf_version` or without `genesis`. 24 positive and 22
  negative vectors and 9 negative documents in all.
- `verifier/`: builds `spec/2.0/reference-verifier.rs` as a library and runs
  every vector against it, with the vector, negative, document and chain counts
  pinned. For every negative it also shows that a reader without the failing
  check computes the stored hash, and it walks every negative that carries
  `record` in place inside the chain. CI runs it on every pull request and every
  push to `main`, with a time limit, and checks that every test ran.


### Changed

- Section 4.2.1: the `$repeat` directive belongs to the vectors file. A loader
  expands it in `vectors[].record` only; a document never carries it, and a
  verifier never expands it. 4.2.1 now comes before 4.2.2.
- Section 4.4: the NULL-delivery rule is scoped to the held call, and a present
  `response_hash_delivered` is what the producer had written or was writing when
  it recorded the decision, not evidence of receipt. `client_disconnected` means
  the producer found the client gone.
- Section 4.7.1: the shutdown definition stands as written, and the Vigil 2.3.2
  race, in which a hold that read the shutting-down flag before it was set and is
  inserted after the drain is never recorded as `shutdown_deny`, is in appendix
  A.1.
- Section 7 rule 2: an `event_kind` is the stated exception to "an unknown token
  is not a failure", because it selects the field table. Rule 2's 27-element
  check applies to a present `features_canonical`; a NULL is rule 1's.
- Sections 5.1 and 7.1 agree: the re-root is the pattern for every future format
  tag.
- Section 9 says what the response hashes record, that members outside the
  records are covered by no hash, and that the carried anchor and genesis are
  self-asserted.
- Section 8: criterion 1 is marked historical, criterion 3 measures a hasher,
  not a full verifier, and is marked not met for 2.1.0, and criterion 6 says
  which cases v2.0.0 accepted.
- Section 6's table compares the device's store with its keychain, and does not
  apply to a document. Section 4.7b says the anchor written after a graceful
  `shutdown` record covers it, and that a `shutdown_deny` can follow it in the
  unanchored tail.
- Section 8.1 documents every member an implementation reads, and marks the rest
  informative.
- Citations: the header names the files in this repository, says Vigil carries a
  revision 3 copy of the vectors and that the document format is not published,
  defines "Vigil 2.3.2" once, and marks older Vigil citations as history. Paths
  that exist only in Vigil say so.

### Fixed

- `spec/2.0/reference-verifier.rs`:
  - Enforces section 7 rule 1 for every field from the Nullable column of the
    section 4 tables, and for every array element. The 2.0.0 file encoded a NULL
    in any body field or array element as the NULL marker, so a NULL `decision`,
    `verdict`, `held_ms`, `is_anomaly`, array element or `features_canonical`
    verified.
  - Rejects a member outside the record's fields, a `hash` or `event_kind` that
    is not a string, and an object or array where a scalar is declared.
    `preimage()` expands nothing. `record()` decodes a record as a document
    carries it, `hash` and `event_kind` required. `expand_vector_record()` is the
    vectors-file loader, and the only place the directive is expanded; it checks
    member names before it expands anything.
  - `parse_document()` parses a document and rejects a repeated member name, and
    refuses to run under serde_json's `arbitrary_precision`, where `-0` would read
    as the integer 0.
  - `document_format()` rejects a document that declares 1.x and carries 2.x-only
    structure, and one whose declared version section 7 does not recognise.
  - `verify_document()` makes every section 7 check on a 2.x document's text and
    returns its verdict, its findings by code, and what the carried anchor says of
    the tail. It does not walk a 1.0 document. Every error a document can produce
    carries its section 7 code, and a NULL `hash` or `event_kind` is
    `null_field`.
  - Clamps the `$repeat` count before allocating, as Vigil's vigil-verify has
    since `204a776`. A count of 2^63 or more panicked, and a large one allocated
    its size before the field limit was checked.
  - `content_covered` counts content that is a present string, so not NULL, as
    vigil-verify has required present and non-null since `dfba3ad`.
  - The unknown `event_kind` error escapes the kind in full, in both Display and
    Debug. It used Rust's `{:?}`, which passes printable non-ASCII through, so a
    lookalike of a real kind, or an invisible filler character, reached any
    caller that printed the error. The escape writes `\u{..}` for everything
    outside printable ASCII, never `\n`, `\r` or `\t`, which a shell's `echo`
    turns back into line breaks.
  - Its header says what it is: independent of the writer, begun as a copy of
    vigil-verify's preimage module, and ahead of vigil-verify, which gains the
    2.1.0 checks in a later pull request.
- `neg_field_count_mutated` changes the count from 35 to 32, not from 33. Three
  vector notes are corrected: `connection_panicked` says panicked, and the
  `client_disconnected` and `restore` notes match sections 4.4 and 4.4.1.

### Compatibility

- A 2.0.0 verifier still verifies records carrying either new value, because
  section 7 rule 2 makes an unknown token not a failure. 2.0.0 did not say what a
  verifier may do with such a record. The section 7 addition does.
- What 2.1.0 fails that 2.0.0 accepted: a repeated member name (RFC 7493
  section 2.3; RFC 8259 says only that names SHOULD be unique, so this check is
  new in 2.1.0), a member outside the record's fields, the `$repeat` directive in
  a document, a `hash` that is not a string, a 1.x declaration on a document with
  2.x-only structure, a 1.0 array of entries in which an entry does not declare
  1.x, a NULL the section 4 tables forbid, a carried anchor whose `head_hash` is
  not the stored hash of the record it counts to, and a document without
  `records` or `genesis`, with either of the wrong type, or without a declared
  version section 7 recognises. Section 2.2 already
  made any field outside a kind's list a new tag, section 4.2.1 already confined
  the directive to the vectors file, and rule 1 already made a nullability
  violation a failure. Vigil's exporter writes none of them in an export with
  records, and a real 2.0 export from Vigil 2.3.2 verifies under 2.1.0's
  reference verifier. It refuses to export records without a genesis, but exports
  a store with no records and no genesis as `"genesis": null`, which 2.1.0
  rejects (`missing_member`) where 2.0.0 reported it `empty`.
- The reference verifier's interface changed: `schema()` returns the Nullable
  column as a third element, `preimage()` no longer expands `$repeat`,
  `expand_vector_record()` takes the kind, and `record()`, `parse_document()`,
  `document_format()`, `verify_document()` and `PreimageError::code()` are new.

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
