# VOAF 2.0 preimage

Revision 4, spec release 2.1.0. Status: proposed; frozen when spec release 2.1.0
is tagged. Owner: C-store.
Companion vectors: `spec/2.0/test-vectors.json` (revision 4), in this repository.
Vigil carries a revision 3 copy at `docs/specs/voaf-2.0-test-vectors.json`.
Companion reference verifier: `spec/2.0/reference-verifier.rs`, which
`verifier/tests/vectors.rs` runs against every vector. It began as the preimage
module of Vigil's vigil-verify and is now ahead of it: vigil-verify gains these
2.1.0 checks in a later pull request. It is not written from this document;
acceptance criterion 3 asks for a hasher that is, and none is published
(section 8).
Companion document format: `voaf-2.0-document.md`, owned by C-verify. It is not
published. Section 7 defines the four top-level members a verifier reads in a
2.x document, `voaf_version`, `records`, `genesis` and `anchor`, and a verifier
ignores every other top-level member.
Supersedes, for 2.x, the 1.0 hash computation: the Hash Chain Verification
section of this repository's README, and the Hash Computation section of Vigil's
`docs/VOAF_SPEC.md`.

"Vigil 2.3.2" in this document means the source at Vigil commit `c449787`; no
2.3.2 release is tagged at the time of writing. Other citations of Vigil source
by file and line describe the tree when revision 3 was written, before C.2
landed, and are kept as history; they are not claims about Vigil 2.3.2.

This document defines the exact bytes hashed for every chained record, and, in
section 7, the four top-level members of a 2.x document a verifier reads and the
checks it makes. The rest of the envelope belongs to the document format.
Nothing in Track C may define or vary the preimage.

### Revision history

Revision 1 was rejected by adversarial review with three proven collision
classes: empty scalar and empty array encoded identically, integer and string of
the same digits encoded identically, and an array could bleed across a differing
field count to produce a byte-identical preimage carrying different real
content. Revision 2 closed all three with typed markers and additionally typed
the NULL marker. Revision 3 reverts the typed NULL per owner ruling, adds
content length and the re-rooted chain, and states the limits.

Revision 1 and 2 vectors are withdrawn, not amended.

Revision 4 is spec release 2.1.0. It changes no preimage byte, no field and no
hash, so the format tag stays `voaf-2.0`.

A 2.0.0 verifier accepts records that carry text no hash covers: a member no
table declares, a second member with the same name, or the vectors-file `$repeat`
directive with anything written beside it. Revision 4 forbids each inside a
record, by validation alone: the document is parsed with no repeated member name,
and section 7 rule 1 lists every check a record makes to decode. Members outside
the records stay outside every hash, the document's declared format among them
(section 9), and section 7 says which of them a verifier reads and what it does
with each.

It also adds two `gate_decision.decision` tokens (section 4.7.1), defines every
(`verdict`, `decision`) pair and what an allow is (section 4.4.1), scopes the
section 4.4 NULL-delivery rule to the held call and says what a present delivery
hash shows, corrects the 2.0.0 description of `client_disconnected` as an
erratum (section 7.1), says how a verifier treats a pair it does not recognise
and how that vocabulary is versioned, defines the document members a verifier
reads and the checks it makes on the chain and the carried anchor, and gives
every check a code and a verdict (section 7), lists where Vigil 2.3.2 does not
meet the definitions (appendix A), and fixes the citations. The reference
verifier makes every section 7 check on a 2.x document, though it does not walk
a 1.0 document, and the vectors file gains six positive and eighteen negative
vectors and thirteen negative documents. No revision 3 record, hash or chain
value changed; one mutation description and three vector notes were corrected.


## 1. Why this replaces the v1 construction

The v1 preimage, at `vigil-store/src/lib.rs:468-475`:

```
SHA256(prev_hash || id || timestamp_rfc3339 || features_json)
```

`user_message` and `ai_response` are not inputs. A v1 chain proves that a record
existed in a given order relative to its neighbours. It does not prove what the
record said, and no version of this chain proves when anything happened
(section 9). Anyone with write access to `vigil.db` can rewrite every captured
prompt and response and `verify_chain` still reports all entries clean.

The version is 2.0, not 1.1, because the Versioning Policy in Vigil's
`docs/VOAF_SPEC.md`
classifies a change to the chain verification algorithm as major.

## 2. Encoding primitives

The preimage is a byte string. Not JSON. No key ordering, no number formatting,
no float anywhere in the evidentiary path.

Every field encodes as **one marker byte**, and for non-NULL fields a **4-byte
big-endian length or count** followed by the payload. One rule for every field,
so a verifier is a single loop.

| Marker | Meaning | Encoding |
| --- | --- | --- |
| `0x00` | NULL | marker only, no length, no payload |
| `0x01` | string | `0x01` \|\| `u32be(byte_len)` \|\| UTF-8 bytes |
| `0x02` | integer | `0x02` \|\| `u32be(byte_len)` \|\| decimal ASCII |
| `0x03` | bool | `0x03` \|\| `u32be(1)` \|\| `0x31` true, `0x30` false |
| `0x04` | array | `0x04` \|\| `u32be(element_count)` \|\| each element fully encoded, marker included |

Array elements are **homogeneous**, of the element type declared in section 4,
and are **never NULL**. Nested arrays do not occur and are not legal.

The four non-NULL markers carry the type. That is what closes revision 1's
collisions:

- NULL `0x00`, empty string `0x01 00000000`, and empty array `0x04 00000000` are
  three distinct byte strings.
- Integer `59` is `0x02 00000002 3539`; string `"59"` is `0x01 00000002 3539`.
- Bool `true` is `0x03 00000001 31`; integer `1` is `0x02 00000001 31`.
- An array can no longer be read as a scalar of the same leading count, so the
  bleed collision is closed at byte 0 of the field.

**NULL is one byte and carries no type.** A NULL string, integer, bool and array
are the same byte. This is deliberate: a field's type is fixed per tag by the
tables in section 4 and cannot vary within a tag, so a type change is a tag bump
(section 2.2) rather than something the encoding must detect. Acceptance
criterion 4 is worded accordingly.

Integers are decimal ASCII, `-` for negative, no leading zeros, `0` for zero.
`-0`, a leading `+`, leading zeros, and any payload that is not valid decimal
ASCII are each a verification failure, never a coercion.

Strings are the raw stored bytes interpreted as UTF-8. No normalisation, no
escaping, no BOM. SQLite TEXT can hold byte sequences that are not valid UTF-8;
a value that does not decode is a verification failure at that index. A producer
must never decode lossily, because two distinct stored blobs would then map onto
one preimage. See 4.2.2 for what a producer does instead.

A verifier does **not** validate the shape of a hash-valued field. A 63-character
or uppercase digest verifies clean if it hashes clean, because the digest is
input to the preimage rather than something the format interprets. Shape
validation belongs to whatever produces the value.

Hash-valued fields (`prev_hash`, `predecessor_document_sha256`,
`predecessor_head_hash`, `anchor_head_hash`, `observed_head_hash`,
`response_hash_upstream`, `response_hash_delivered`, `user_message_sha256`,
`ai_response_sha256`) are hashed as their 64 lowercase ASCII hex bytes. They are
**never** hex-decoded before hashing.

### 2.1 Limits

| Limit | Value |
| --- | --- |
| maximum bytes in any string or integer field | 2^20 (1,048,576) |
| maximum elements in an array | 2^16 (65,536) |
| maximum bytes in one preimage | 2^24 (16,777,216) |

All three limits are **inclusive**: exactly 2^20 bytes, exactly 2^16 elements and
exactly 2^24 preimage bytes are each legal; one more is not.

The per-field byte limit applies to array **elements** as well as to fields.

The per-preimage bound is not redundant. Without it the per-field and per-array
limits still permit 2^16 elements of 2^20 bytes, a 64 GiB preimage, which is the
class of read the limits exist to prevent.

The byte limit applies to **every** string and integer field, not only the two
content fields. Scoping it to content alone would leave the u32 wrap open on
every other field.

A verifier **hard-fails** on any declared length or count that exceeds these.
This is not advisory. Without a stated maximum, a producer or verifier writing
`len as u32` truncates silently, so a field of length 2^32 + n shares a header
with a field of length n and 4 GiB of attacker-chosen content is read as the
fields that follow. That collision was demonstrated.

"Declared length" means the `u32be` header emitted in the preimage, never the
value of a `_length` field. `user_message_length` is a data value describing the
original content and is routinely larger than the cap on a truncated record, so
limit-checking it would reject exactly the records it exists to describe.

### 2.2 Field count and domain separation

Field 1 is the literal string `voaf-2.0`, encoded as a string field like any
other: `0x01 || u32be(8) || "voaf-2.0"`. It is not raw bytes.

Field 2 is an integer field whose value is taken from the table below. The table
is normative; it is not recomputed from a producer's field list, so a producer
whose list has drifted produces a hash mismatch rather than a self-consistent
wrong record.

| Event kind | Field count |
| --- | --- |
| `interaction` | 35 |
| `gate_decision` | 23 |
| `chain_upgrade` | 11 |
| `chain_truncation` | 11 |
| `lifecycle` | 10 |

The field count is **defence in depth, not the mechanism that closes the bleed
collision**. Revision 2 credited it with that and was wrong: the `0x04` array
marker closes the bleed on its own, and the field count does not separate
`chain_upgrade` from `chain_truncation`, which both encode field 2 as
`02000000023131`. It is retained because it binds a record's arity into its hash,
so a schema drift that slips through without the tag bump below surfaces as a
hash mismatch instead of a self-consistent wrong record.

**A verifier never compares field 2 against the number of fields a record
carries.** It takes the declared count, encodes it, and lets any disagreement
surface as a hash mismatch. An earlier wording implied an arity cross-check; an
implementer built one and it hard-failed `neg_field_count_mutated`, which
declares 32 for an `interaction` record, whose count is 35. That vector exists to
show the hash moves when the count is mutated, not to be accepted as a valid
document.

**Any change to any event kind's field list, field order, or field types
requires a new tag.** Adding a field to an existing kind is not a minor
revision. This is what makes the untyped NULL safe.

### 2.3 Record hash

`SHA256(preimage)`, rendered lowercase hex. The preimage is the concatenation of
its fields in declared order, with no separators and no trailing bytes.

## 3. Scaled integers

Scores are stored and hashed as `i64` scaled by 1,000,000. The producer rounds
half to even exactly once, at write time, into the authoritative
`features_canonical` column. Verifiers never convert. They read integers.

The `f64` the detectors consume is derived from `features_canonical` on the
store read path. `features_json` becomes a non-evidentiary cache.

`anomaly_score_canonical` gets the same treatment: a new `i64` column, scale
1,000,000, rounded half to even once from the detector `f64`. The existing
`anomaly_score REAL` column (live range 0.0 to 0.329008131231609) is retired by
C.2 and its readers repointed.

`features_canonical` MUST be present with exactly 27 elements for
`event_kind = interaction`.

v1 rows are backfilled into `features_canonical` during migration. This is safe
and it is required: v1 rows are not part of the 2.0 chain (section 5.1), so
their hashes do not depend on the column, and without the backfill
`all_features()` and `features_since()` return nothing for them once the
detector read path is repointed off `features_json`.

The 27 slots, uniformly scaled:

| Slots | Meaning |
| --- | --- |
| 0 to 8 | `action_class`, one-hot |
| 9 to 17 | `scope`, multi-label |
| 18 | `agency` |
| 19 | `directionality`, may be negative |
| 20 | `reversibility` |
| 21 to 24 | `interaction_type`, one-hot |
| 25 | `delegation_depth` |
| 26 | `has_counterparty` |

Counts and booleans are scaled too, so there is one interpretation rule.

### 3.1 A dimension is currently lost

`vigil-core/src/lib.rs:223` declares `FEATURE_DIM = 26`; the inventory needs 27.
`to_array()` at `:239-250` writes `interaction_type` into `arr[21..25]` then
`arr[24] = delegation_depth`, overwriting `interaction_type[3]`.

This corrupts no existing hash, because `features_json` serialises the struct
rather than the flattened array. C.2 raises `FEATURE_DIM` to 27. Nothing
persisted is invalidated: `baselines.profile_json` holds scalar statistics and
fixed-width distributions computed by SQL over `features_json`, and there is no
persisted detector state.

## 4. Field tables

Every record begins with this envelope:

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 1 | format tag, literal `voaf-2.0` | string | no |
| 2 | field count | integer | no |
| 3 | `seq` | integer | no |
| 4 | `prev_hash` | string, 64 lowercase hex | no |
| 5 | `event_kind` | string | no |
| 6 | `id` | string | no |
| 7 | `timestamp_us` | integer | no |

`seq` is a monotonic 0-based chain position, stored in its own column and
hashed. It is what "in order" means in section 7. Revision 1 left order implicit
in `rowid`, which is not hashed, is not preserved across a table rebuild, and
does not exist in an exported document. The encryption migration copies
`interactions`, so relying on `rowid` would have broken the chain during our own
migration.

`timestamp_us` is microseconds since the Unix epoch, UTC. The RFC 3339 string
shown in the UI is derived from it at render time. The existing
`timestamp TEXT NOT NULL` column is retained for **filtering** compatibility and
is explicitly not evidence. It is not retained for ordering: nothing in the
workspace orders `interactions` by `timestamp`, and the nine chained-table reads
all order by `rowid`, which section 4's `seq` replaces.

### 4.0 Storage of non-interaction event kinds

`interactions` declares `provider`, `interaction_type`, `action`, `scope`,
`features_json`, `risk_tier`, `is_anomaly` and `policy_action` NOT NULL, so a
`chain_upgrade`, `gate_decision`, `chain_truncation` or `lifecycle` record cannot
be inserted into it as the table stands. Section 4.9 requires all kinds to share one chain in
one `seq` order, so they must share one table.

Resolving that is a storage decision, not a preimage decision, and it is
specified in the day-one data contract alongside `insert_event`. This document
constrains it only as follows: whatever the tables become, the fields listed in
sections 4.1, 4.4, 4.5, 4.6 and 4.7b are what get hashed, and `seq` is unique and
gapless across all kinds.

A stored value that violates a field's declared nullability is a verification
failure at that index, never a coercion.

### 4.1 `interaction`, fields 8 to 35

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 8 | `provider` | string | no |
| 9 | `model` | string | yes |
| 10 | `interaction_type` | string | no |
| 11 | `conversation_ref` | string | yes |
| 12 | `client_ref` | string | yes |
| 13 | `user_message` | string | yes |
| 14 | `user_message_sha256` | string | yes |
| 15 | `user_message_length` | integer | yes |
| 16 | `user_message_truncated` | bool | no |
| 17 | `ai_response` | string | yes |
| 18 | `ai_response_sha256` | string | yes |
| 19 | `ai_response_length` | integer | yes |
| 20 | `ai_response_truncated` | bool | no |
| 21 | `action` | string | no |
| 22 | `scope` | string | no |
| 23 | `features_canonical` | array of integer, exactly 27 | no |
| 24 | `risk_tier` | string | no |
| 25 | `anomaly_score_canonical` | integer | yes |
| 26 | `is_anomaly` | bool | no |
| 27 | `policy_action` | string | no |
| 28 | `matched_policy` | string | yes |
| 29 | `blocked` | bool | yes |
| 30 | `block_reason` | string | yes |
| 31 | `policy_id` | string | yes |
| 32 | `gate_layer` | integer | yes |
| 33 | `tap_certificate_id` | string | yes |
| 34 | `scope_violation` | bool | no |
| 35 | `execution_gate_id` | string | yes |

### 4.1.1 `conversation_ref` and `client_ref`

`conversation_ref` is the conversation identifier the protocol carries on the
wire: the claude.ai and chatgpt.com conversation ids, and OpenAI Responses
`previous_response_id`. It is NULL for the Anthropic Messages API and any other
protocol that carries none. Nothing extracts it today; `conversation_id` appears
in this tree only in test fixtures at `vigil-proxy/src/proxy.rs:2698` and
`:2806`.

`client_ref` is the calling client. It is the `agent_id` that
`extract_agent_id` already computes at `vigil-proxy/src/identity.rs:166-185`:
the explicit `x-agent-id` header when present, otherwise
`SHA-256(User-Agent + endpoint)` truncated to 16 hex characters. That value is
computed today and persisted nowhere.

Both are hashed because the session rule in the data contract consumes them, and
`session_id` is only safe to leave out of the preimage while every input to its
derivation is itself hashed. Adding them now costs two nullable fields; adding
them after the freeze would cost a tag bump.

One honest limit: `client_ref` does not separate two tabs of the same browser,
because their User-Agent and endpoint are identical. Only `conversation_ref`
does. On a protocol that carries no conversation id, two concurrent
conversations from one client inside the idle gap will group as one session, and
the Vault tab will show them merged. That is a capture limitation, not a
grouping bug, and it is why `conversation_ref` is worth a hashed field.

`execution_gate_id` has a column (`vigil-store/src/lib.rs:273`) and no producer
anywhere in the tree. It is hashed now, always NULL until Track A writes it, so
Track A does not later require a tag bump.

`intent_vector` is excluded. It has no column, is populated only in memory at
`vigil-pipeline/src/lib.rs:456`, and hashing an unpersisted field would make
every record unverifiable on read.

### 4.2 Content fields

Content is stored in full, capped at 2^20 bytes per field.

**Truncation cuts at the last UTF-8 code point boundary at or below the cap**, so
a stored value is always valid UTF-8 and may be up to three bytes below
1,048,576. The `_truncated` flag is set whenever the full content exceeded the
cap in bytes.

**No ellipsis or marker is appended.** Today `vigil-pipeline/src/lib.rs:848-858`
appends a literal `...`, which is why the live maximum is 503 rather than 500. A
marker inside the value makes a message genuinely ending in `...`
indistinguishable from a truncated one and makes `_sha256` uncheckable against a
candidate original.

`_sha256` is `SHA256` of the **full** content, computed before any truncation,
hex lowercase. `_length` is the **byte** length of the full content, not the
character count. Both are NULL if and only if the source content did not exist.

`_sha256` and `_length` are present **whenever content existed**, regardless of
whether the content itself was stored. This is what makes the
`store_raw_content` off mode coherent: see section 4.3.

Binary and compressed bodies are `transport` events under Track B's classifier
and never enter these fields.

### 4.2.1 The repeat directive belongs to the vectors file

Two vectors carry content larger than is reasonable to check into a file. In a
vector's `record`, and nowhere else, a field's value may be the object

```
{"$repeat": {"char": "<single character>", "count": <integer>}}
```

which denotes that character repeated `count` times, encoded UTF-8. "Character"
means one Unicode scalar value, and `count` is a non-negative integer. The object
has exactly the one member `$repeat`, and its value has exactly the members
`char` and `count`. The **expanded** value is subject to the section 2.1 limits
exactly as a literal value would be.

This is a property of the vectors file, not of the preimage or of any stored
record. A loader for the vectors file expands the directive in `vectors[].record`
before the record is decoded, and nowhere else: not in `negative_vectors[]`,
whose records are written as a document carries them. So `neg_field_over_limit`
carries its 1,048,577-byte `user_message` literally, the one value in the file
past a reviewable size.

**A document never carries the directive, and a verifier never expands it.** In
a document it is a JSON object in a field section 4 declares a string, and an
object or an array where a section 4 table declares a string, an integer or a
bool does not decode (section 7 rule 1). A verifier that expanded it in a
document would hash the expansion and nothing else, so any member written beside
`$repeat`, or inside it, would be text no hash covers. `neg_repeat_in_document`
is that case.

The directive is specified here because acceptance criterion 3 asks that a
hasher written from this document alone reproduce every positive vector hash, and
without this paragraph two of them cannot be reproduced.

### 4.2.2 A body that is not valid UTF-8

**An intercepted body that does not decode as UTF-8 is stored as NULL content
with `_sha256` and `_length` computed over the bytes exactly as received, and
`_truncated` false.**

Nothing is substituted. Neither a lossy decode nor a placeholder string may be
hashed in its place: a lossy decode maps every invalid sequence to U+FFFD, so two
distinct bodies collapse to one digest, and a placeholder produces a record whose
digest covers a string the traffic never contained while reading as ordinary
content to anyone verifying it.

This shares its shape with the `store_raw_content` off case in 4.3: content NULL,
digest and length present. That is correct rather than ambiguous. Both mean the
same evidentiary thing, which is that the digest and length are known and the
text is not retained, and a party holding the original can verify either. The
difference between them is operational, not evidentiary, and the format does not
record it.

### 4.3 Audit without memory

`store_raw_content` (`vigil-core/src/lib.rs:649`, default `false` at `:673`) is
read nowhere today, so content has always been stored regardless of it. It
becomes a user-visible setting, "Store conversation content", **default on**,
because the Vault is the product.

When off, `user_message` and `ai_response` are stored NULL while `_sha256` and
`_length` are still computed and stored, and the Vault tab states that memory is
off. The record still proves what was said to any party holding the original,
while Vigil retains none of it.

Three content-derived fields NULL together means no content existed.
`_sha256` and `_length` present with the content field NULL means content
existed and was deliberately not retained. Vectors `interaction_minimal` and
`interaction_content_off` pin the distinction.

### 4.4 `gate_decision`, fields 8 to 23

Inlined rather than referenced, because Vigil's `docs/specs/execution-gate-v1.md` is not
in this repository. That file's section 10 is informative; this table is normative.

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 8 | `gate_id` | string | no |
| 9 | `interaction_id` | string | yes |
| 10 | `provider` | string | no |
| 11 | `protocol` | string | no |
| 12 | `tool_call_id` | string | yes |
| 13 | `tool_name` | string | yes |
| 14 | `class` | string | no |
| 15 | `rule_ids` | array of string | no |
| 16 | `verdict` | string | no |
| 17 | `decision` | string | no |
| 18 | `held_ms` | integer | no |
| 19 | `snapshot_ids` | array of string | no |
| 20 | `response_hash_upstream` | string | yes |
| 21 | `response_hash_delivered` | string | yes |
| 22 | `actor` | string | no |
| 23 | `policy_version` | string | no |

An empty `rule_ids` is a present array with count 0, not NULL.

`response_hash_delivered` is NULL when the producer never wrote anything for the
held call: neither the call nor anything in its place. The `client_disconnected`
and `connection_panicked` outcomes are that case. On a streamed response the
client may already have received the events before the held call; what it never
received is the call, and recording a delivery hash would assert a delivery that
did not happen. A verifier must not treat a NULL there as missing data.
`connection_panicked` also carries a NULL `response_hash_upstream` (section
4.7.1).

A present `response_hash_delivered` is the SHA-256 of what the producer had
written, or was writing, to the client for that response when it recorded the
decision. That can be less than it went on to write for the call: a producer
that releases a message's calls together records a hash over output that does
not yet include them. A present hash is not evidence that the client received
anything (section 9).

`client_disconnected` means the producer found, while the call was held, that
the client had gone. A producer that does not find it records the decision the
hold reached instead, with both hashes present. Appendix B says where Vigil 2.3.2
looks.

### 4.4.1 What each (`verdict`, `decision`) pair records

Added in revision 4, spec release 2.1.0. This is the meaning section 7.1 refers
to. A record's meaning is its (`verdict`, `decision`) pair, never `verdict`
alone. On every pair but (`allow`, `restore`), `verdict` says only whether the
gate's policy concluded that the call should be held.

"Delivered" means the producer released the call's own events to the client,
not a substitute for them. A producer cannot see whether a client received or
executed a call, so release is the most a record attests, and it is the
producer's own account (section 9). A call that was not delivered was not
executed through this producer.

| `verdict` | `decision` | Decided by | Recorded by | The call delivered | Written in its place |
| --- | --- | --- | --- | --- | --- |
| `allow` | `allow` | the gate's policy, which did not hold the call | the gate | yes | nothing |
| `hold` | `allow` | the gate's policy, which would have held the call, under a gate set to observe only | the gate | yes, without waiting | nothing |
| `hold` | `user_approve` | a person, through a decision surface | the gate | yes, after the hold | nothing |
| `hold` | `always_allow` | a person, through a decision surface, allowing calls like it from then on | the gate | yes, after the hold | nothing |
| `hold` | `user_deny` | a person, through a decision surface | the gate | no | deny text |
| `hold` | `timeout_deny` | the producer, when the hold window passed with no decision | the gate | no | deny text |
| `hold` | `client_disconnected` | nobody: the producer found during the hold that the client had gone | the gate | no | nothing |
| `hold` | `shutdown_deny` | the producer, shutting down (section 4.7.1) | the gate | no | deny text |
| `hold` | `connection_panicked` | nobody: the task serving the connection panicked during the hold (section 4.7.1) | the producer, outside the path that decides holds | no | nothing |
| `allow` | `restore` | whoever asked the producer to restore a file | the producer | no call is involved | the snapshot, over the file it was taken from |

"A person, through a decision surface" is what the record attests: a decision
that reached the producer through a surface it offers people. Whether a person
was at that surface is outside the record.

**An allow** is a record whose pair says the call was delivered: (`allow`,
`allow`), (`hold`, `allow`), (`hold`, `user_approve`) and (`hold`,
`always_allow`). Section 7 rule 2 uses the word in this sense. A verifier that
counts allows counts these four pairs by the pair: (`hold`, `allow`) is an allow,
and (`allow`, `restore`) is not.

**(`hold`, `allow`) is not a released hold.** The call never waited. `verdict`
`hold` records what the policy concluded, and `decision` `allow` records that a
gate set to observe only delivered the call anyway. `held_ms` is 0. A verifier
must not count it as a hold that a person released.

**(`allow`, `restore`) is not a tool-call decision.** It records the producer
writing a pre-execution snapshot back over the file it was taken from. No tool
call and no response is involved: `tool_call_id` and `tool_name` are NULL,
`held_ms` is 0, and `snapshot_ids` holds the restored snapshot's id. The two hash
fields are file digests, not response hashes: `response_hash_upstream` is the
SHA-256 of the file at that path before the restore, NULL when no file could be
read there, and `response_hash_delivered` is the SHA-256 of the snapshot content
written over it. `verdict` `allow` means only that the restore went ahead.

**The response hashes on every other pair**, where section 4.4 or 4.7.1 does not
make them NULL. `response_hash_upstream` is the SHA-256 of the upstream response
as the producer had received it when it recorded the decision. `response_hash_delivered` is as section 4.4 says: the
SHA-256 of what the producer had written, or was writing, to the client for that
response when it recorded the decision, and NULL when it never wrote anything for
the decided call. Neither shows that the client received anything (section 9).

A pair this table does not list has no meaning in this release; section 7 rule 2
says how a verifier treats it. Appendix A lists where Vigil releases do not meet
these definitions, and appendix B describes how Vigil 2.3.2 writes the records
that do.

### 4.5 `chain_upgrade`, fields 8 to 11

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 8 | `predecessor_format_version` | string | yes |
| 9 | `predecessor_document_sha256` | string | yes |
| 10 | `predecessor_record_count` | integer | yes |
| 11 | `predecessor_head_hash` | string | yes |

**Record 0 of every 2.0 chain is a `chain_upgrade`**, and its `prev_hash` is the
anchored genesis of section 5. All four predecessor fields are NULL on a fresh
install. Every external 2.3.0 install is that case, since there are no external
v1 users.

### 4.6 `chain_truncation`, fields 8 to 11

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 8 | `anchor_entry_count` | integer | no |
| 9 | `anchor_head_hash` | string | no |
| 10 | `observed_entry_count` | integer | no |
| 11 | `observed_head_hash` | string | no |

### 4.7 Wire token vocabulary

Normative, and the token table below wins over any attribute.

C.2 applies `#[serde(rename_all = "snake_case")]` to `InteractionType`,
`ActionCategory`, `ScopeTag`, `RiskTier` and `PolicyAction`. **`Provider` keeps
`rename_all = "lowercase"`, which it already has.** snake_case on `OpenAI` yields
`open_a_i`, not `openai`, because serde inserts a separator before every
uppercase letter after the first. Applying snake_case uniformly, as revision 3
first said, would have silently renamed the most common provider token in the
store.

The live store holds `"Direct"`,
`"InformationRetrieval"`, `"Tier0"`, double-JSON-encoded with literal quotes
(`vigil-store/src/lib.rs:492-503`). The preimage uses the bare token.

| Enum | Tokens |
| --- | --- |
| `provider` | `openai`, `anthropic`, `google`, `mistral`, `unknown` |
| `interaction_type` | `direct`, `delegated`, `agent_to_agent`, `cascaded` |
| `action` | `information_retrieval`, `analysis`, `creation`, `communication`, `transaction`, `decision`, `configuration`, `agent_coordination`, `unknown` |
| `scope` | `financial`, `health`, `legal`, `identity`, `social`, `professional`, `personal`, `technical`, `general` |
| `risk_tier` | `tier0`, `tier1`, `tier2`, `tier3` |
| `policy_action` | `allow`, `flag`, `escalate`, `block` |
| `event_kind` | `interaction`, `gate_decision`, `chain_upgrade`, `chain_truncation`, `lifecycle` |
| `gate_decision.verdict` | `allow`, `hold` |
| `gate_decision.decision` | `allow`, `user_approve`, `user_deny`, `timeout_deny`, `always_allow`, `restore`, `client_disconnected`, `shutdown_deny`, `connection_panicked` |
| `lifecycle.event` | `startup`, `shutdown`, `protection_on`, `protection_off`, `reanchored` |

Section 4.4.1 defines each `gate_decision.decision` value.

### 4.7.1 `shutdown_deny` and `connection_panicked`

Added in revision 4, spec release 2.1.0. Each records a held call that no person
decided, and each is written with `verdict` = `hold`. Neither is a person's deny,
and neither is an allow (section 4.4.1).

**`shutdown_deny`**

- Written by: the producer's gate, on its own authority.
- When: the producer is shutting down. Its shutdown sequence denies every hold
  in its queue when the sequence runs, and a hold offered after shutdown has begun
  is refused as it is made and recorded as `shutdown_deny` too.
- Whether the held action executed: no. The producer writes deny text to the
  client in place of the tool call, the same substitution it makes for
  `user_deny`, so the client never receives the call. `response_hash_upstream`
  and `response_hash_delivered` are both present, and they differ.
- Where it lands: the producer records it while it shuts down, so a
  `shutdown_deny` record can follow the `lifecycle` `shutdown` record, can
  fall after the head anchor (the unanchored tail of section 6), and is absent if
  the process ends before the task records it.

**`connection_panicked`**

- Written by: the producer, outside the path that decides holds.
- When: the task serving the client connection panicked while the hold was still
  open and undecided. The producer removes each hold still open on that
  connection, so no later decision can act on it, and records it. A hold already
  resolved but not yet recorded is not open, and is not recorded as
  `connection_panicked`.
- Whether the held action executed: no. The task that held the call and the
  client connection is gone. The call is never written to the client, and the
  client sees its connection close. `response_hash_upstream` and
  `response_hash_delivered` are NULL: the record is written after the task that
  read the response is gone, and nothing was delivered for the call.

"Did not execute" is the producer's account of what it delivered, the same
self-attestation section 9 describes for the response hashes. No record can show
what a client did with a call it obtained some other way.

### 4.7b `lifecycle`, fields 8 to 10

| # | Field | Type | Nullable |
| --- | --- | --- | --- |
| 8 | `event` | string | no |
| 9 | `app_version` | string | no |
| 10 | `reason` | string | yes |

`event` is one of `startup`, `shutdown`, `protection_on`, `protection_off`,
`reanchored`.

This kind exists because `Store::log_shutdown`
(`vigil-store/src/lib.rs:1014-1058`) already appends a real chained record on
graceful shutdown, with an `event_type` buried in its features JSON. It has zero
callers today, but ruling C wires a graceful shutdown path, and the moment it
fires it would write a record section 7 rule 2 hard-fails. It is given a proper
kind rather than being overloaded onto `background`.

`protection_on` and `protection_off` are **evidentiary**. A verifier seeing a
time gap between records can distinguish deliberate disablement from missing
evidence only because these records exist. Without them, every period of
disabled interception is indistinguishable from destroyed evidence.

`reanchored` is a fifth value beyond the four in the ruling. Section 6 requires
that a re-anchor after the `unanchored` state be recorded as a chain event, and
none of the four covers it. Flagged as an addition rather than made silently.

On graceful shutdown the head anchor is written **immediately after** the
`shutdown` record commits, so the anchor covers the `shutdown` record and every
record before it. That is not always the chain head: a `shutdown_deny` the
producer records while it shuts down can follow the `shutdown` record, and it
then falls in the unanchored tail of section 6 (section 4.7.1).

### 4.8 `transport` and `background` are not specifiable yet

Both are named in the brief and neither has a field definition anywhere. Adding
them later requires a new tag under section 2.2. Flagged as a decision, not an
omission.

### 4.9 Completeness

Every persisted column of an evidentiary row appears in some preimage, or is
named in section 9 as excluded. There is no third category. All event kinds are
appended to a single chain in one `seq` order.

## 5. Genesis and the re-root

```
genesis = SHA256(b"vigil-genesis" || install_nonce_raw_32)
```

`install_nonce` is 32 random bytes generated at first launch, held in the login
keychain hex-encoded because `ca_keychain.rs` `load()` round-trips through UTF-8.
It is **hex-decoded to 32 raw bytes** before hashing. The section 2 rule that
hash-valued fields are never hex-decoded governs the enumerated preimage
*fields*; `install_nonce` is not one of them and never appears in a preimage.
Both operands are fixed length so the concatenation is unambiguous.

The genesis is carried in no record. A verifier reads it from the document's
top-level `genesis` member (section 7), which Vigil's exporter writes.

The property this buys, stated narrowly: **a party who has never observed any
record or export from this install cannot guess its genesis.** Revision 1 said
"a chain cannot be fabricated off-device", which is false. The genesis appears in
every exported document, so anyone who has seen one export can reproduce it and
build a chain from it. The chain is unkeyed. Anchoring raises the cost of
fabricating a chain for an install you have never seen; it does not prevent
forgery by anyone who has.

The nonce carries no identity weight. `instance_id` is a separate login-keychain
item, seeded on first upgrade from the existing genesis-derived value so the
internal installs keep their cloud registrations.

### 5.1 Migration order

The 2.0 chain does not continue the v1 chain. It re-roots at the genesis, and
record 0 commits to the v1 chain as an archived artifact.

1. `PRAGMA wal_checkpoint(TRUNCATE)` so each main file is self-contained.
2. Export the v1 chain as a 1.0 document to
   `~/Library/Application Support/vigil/archive/voaf-1.0-<date>.json`.
3. Verify that document in 1.0 mode, link-only.
4. Compute its `SHA256`.
5. Write record 0, the `chain_upgrade`, carrying all four predecessor fields:
   `predecessor_format_version` (`"1.0"`), `predecessor_document_sha256` (the
   digest from step 4), `predecessor_record_count`, and `predecessor_head_hash`
   (the last v1 hash).

v1 rows remain in `interactions` with `chain_version = 1`, are excluded from 2.0
verification, and are shown in the dashboard with the archive reference.
**Nothing is deleted.** This is the pattern for every future format tag.

## 6. Head anchor

A login keychain item holds `entry_count` and `head_hash`. `head_hash` is the
stored record hash of the highest-`seq` record in the chain, and `entry_count` is
the number of records in it. The chain is every record carrying
`chain_version = 2`, in `seq` order, with no gaps.

**Durability.** The store commit must be durable before the anchor is written,
so the anchor lags and never leads. `Store::open` currently sets
`PRAGMA synchronous = NORMAL` alongside WAL (`vigil-store/src/lib.rs:33`), under
which a committed transaction can be lost to power failure. The anchor would then
lead the store and a clean machine would report `truncated`.

`vigil.db` therefore runs `PRAGMA synchronous = FULL` **globally**, not per
commit. It is an audit log: durability beats throughput, the insert path is
already off the user's latency path, and a global setting cannot be forgotten by
a future caller the way a per-commit one can. The other four databases keep
`NORMAL`.

**Atomicity.** The anchor write is double-buffered. `ca_keychain.rs` implements
`store()` as delete-then-add, which leaves a window where the item does not
exist, so a single item cannot be updated atomically. Two keychain accounts,
`vigil-head-anchor-a` and `vigil-head-anchor-b`, are written alternately, each
carrying a monotonic generation counter; the reader takes the higher generation
that parses. A torn write costs one generation, never the anchor.

The table compares the device's store with its keychain anchor. It does not apply
to an exported document: section 7 is the complete set of checks a verifier makes
on one, the anchor the document carries included.

| Store versus anchor | Chain state |
| --- | --- |
| anchor absent or `entry_count` 0, no rows | `empty` |
| anchor absent, rows present | `unanchored`, never `verified`. Re-anchor on the next checkpoint and record a `lifecycle` event with `event` = `reanchored` |
| anchor present with `entry_count` > 0, store has zero rows | `lost` |
| anchor present but unreadable | `unanchored`, reported distinctly from an absent anchor |
| rows equal anchor, hash matches | `verified` |
| more rows than anchor, anchored prefix matches | `verified`, with an explicitly reported unanchored tail of N records |
| more rows than anchor, anchored prefix does **not** match | `broken`, reported as chain replaced, not as an unanchored tail |
| fewer rows than anchor | `truncated` |
| rows equal anchor, hash differs at the anchored count | `truncated` |
| linkage or recompute fails | `broken` |

`verified` is never reported for zero rows. This is the fourth badge state for
Track B, recorded as a `chain_truncation` event when the chain resumes, and the
anchor value is carried in the exported document.

The lagging tail is the ordinary steady state, not an alarm. A crash or power
loss leaves rows the anchor has not caught up to, which is the sixth row above.

**`lost` is not `truncated`.** Truncation is partial: some records survive and
the anchor proves more existed. `lost` is total: the anchor survived in the
keychain and the store did not, which is what a wiped data directory or a failed
restore looks like. It is a distinct state because the recovery is distinct.
Record 0 of the replacement chain is a `chain_upgrade` carrying
`predecessor_record_count` and `predecessor_head_hash` **from the anchor** rather
than from a document, with `predecessor_document_sha256` NULL because there is no
archive left to hash. `predecessor_format_version` is the format version of the
chain that was lost: `"2.0"` after a 2.0 store is lost, `"1.0"` only when the loss
predates the migration. The same re-root pattern that handles the 1.0 migration
handles catastrophic loss, and the loss is recorded on the chain rather than
being silently absent.

WAL mode interacts with this directly. All 59 live rows sit in `vigil.db-wal`
while `vigil.db` is 4096 bytes, so a copy of the main file alone contains no rows
and presents as `truncated`. Opening `vigil.db` with `immutable=1` shows no
tables at all. Per ruling C the sidecar checkpoints before any migration or
inspection, and the verifier runbook states that a WAL-mode SQLite file cannot be
opened read-only without directory write access unless it has been checkpointed
first.

## 7. Verification

The document is parsed first. Its text is one JSON value in which no object, at
any depth, repeats a member name (RFC 7493 section 2.3). A parser that keeps one
of two members with the same name has already discarded the other, and the copy
it discards is text no hash covers, so this is checked while parsing, never on the
parsed value. A document that repeats a member name does not verify, and none of
its records is walked (`duplicate_member`). The top-level object is no exception:
of two `records` members a parser keeps one, and the other carries a copy of the
chain that no check reads. `neg_duplicate_member` and
`neg_duplicate_member_mirror` are that case, for a parser that keeps the last copy
and for one that keeps the first, and `doc_duplicate_records` is that case at
the top level. Text that is not one JSON value is not walked either
(`invalid_json`).

Then the document's format is settled: the format check. Its declared version,
`voaf_version`, or `voaf` on each entry of a 1.0 array of entries, is a member
no hash covers, and it decides whether content is checked at all. A declared
version is digits and dots: runs of the ASCII digits `0` to `9` separated by
single dots, such as `1.0.0` or `2.1.0`. A version whose first run is exactly
`1` declares 1.x, and one whose first run is exactly `2` declares 2.x; any other
first run, `01` and `02` included, is not recognised. Anything else, a missing
or non-string version included, is rejected and never walked
(`unrecognised_format`), and so is a top-level value that is neither an object
nor an array of entries each declaring 1.x. A verifier cannot always detect a
relabelled 2.x document: one stripped of every member only 2.x defines reads as
a 1.0 document. The protection is the 1.0 verdict, which never asserts content
integrity (below). What a verifier can detect, it MUST reject: a document that
declares 1.x and carries structure only 2.x defines, a `records` member or an
entry carrying `event_kind`, `seq` or `timestamp_us`, is rejected and never
walked link-only (`format_mismatch`). No 1.0 document carries any of these: the
1.0 schema forbids them on an entry, and Vigil's 1.0 exporter wrote none.
`neg_relabelled_1_0` is that case; a verifier without this check may reject it
first at a link instead (`link_break`), depending on its 1.0 walk.

A 2.x document is an object, and a verifier reads four of its members (the
document member check):

| Member | Holds |
| --- | --- |
| `voaf_version` | a string, the declared version; required |
| `records` | an array, the records; required |
| `genesis` | a string, the section 5 genesis that record 0 links to; required when the record count is 1 or more, and not read when it is 0 |
| `anchor` | an object holding `entry_count`, a non-negative integer, and `head_hash`, a string: the section 6 head anchor as the exporter carried it; optional |

Every other top-level member is ignored, and so is every member of `anchor` but
those two. The document's record count is the number of elements of `records`.
`records` or `genesis` written as `null` counts as absent. A 2.x document
without `records` is rejected and never walked (`missing_member`), and so is one
with a record count of 1 or more and no `genesis` (`missing_member`). One whose
`records` is not an array, or whose record count is 1 or more and whose
`genesis` is not a string, is rejected too (`malformed_member`). Only record 0
links to the genesis, so with a record count of 0 `genesis` is not read,
whatever it holds.

The anchor's `entry_count` is read when it is a JSON number whose value is a
non-negative integer, in any notation (`13`, `13.0` and `1.3e1` are one count,
and a count of 2^64 or more exceeds every record count), and its `head_hash`
when it is a string. An anchor that is absent, `null`, or present and not `null`
with no `entry_count` that can be read gives the verdict of no anchor, but the
three are not the same report: each has its own informational code, which
changes no verdict. `anchor_absent` is a document with no `anchor` member, and
`anchor_null` one whose `anchor` is `null`, as Vigil's exporter writes when the
device has no anchor. `anchor_unreadable` is an anchor present but unreadable,
as the `{"unreadable": true}` Vigil's exporter writes when it cannot read the
device's anchor: it tells an auditor the device had an anchor it could not read,
and a verifier MUST NOT report it the same as a document that never carried one.


The checks below constrain the records, the chain they form, and the anchor
carried with them. Every member outside the records, the declared format, the
genesis and the anchor among them, is covered by no record hash (section 9).

Records are walked in ascending `seq` order; the order in which `records` lists
them is not significant. For each record:

1. Decode every field into its declared type. Each of these is a hard failure at
   that index, with its code:
   - a record that is not a JSON object, `null` included (`wrong_type`);
   - a member other than `seq`, `prev_hash`, `id`, `timestamp_us`, `event_kind`,
     `hash` and the fields section 4 declares for the record's kind
     (`unknown_member`). Section 2.2 makes any other field a new tag, so no
     `voaf-2.0` record carries one, and a member no preimage reads is text no
     hash covers. Vigil's VOAF 1.x specification (`docs/VOAF_SPEC.md`) lets a 1.x
     verifier ignore a field it does not know; that does not carry over to 2.x;
   - a member that is missing: any envelope field, `event_kind`, `hash`, or any
     field section 4 declares for the kind, nullable or not (`missing_field`). An
     absent field is not a NULL, or one hash would have two document encodings;
   - a value of the wrong type that is not NULL: a JSON object or array where the
     table declares a string, an integer or a bool, any other value not of the
     declared scalar type, a non-array where it declares an array, an element
     that is not of the declared element type, or an `event_kind` or `hash` that
     is not a string (`wrong_type`). Nothing in a document is expanded or
     unwrapped (section 4.2.1). A NULL member is never reported as a wrong type;
   - a NULL in a field the table marks not nullable, the envelope fields and
     `features_canonical` included, and a NULL `event_kind` or `hash`
     (`null_field`), and a NULL array element (`null_element`, section 2);
   - a `u32be` length or count header that exceeds a section 2.1 limit
     (`over_limit`). This check is on the header, never on the value of a
     `_length` field.

   `event_kind` names the record's kind. `hash` is the record's stored hash, the
   value rules 3 and 4 use. The parse check, the member check and the type check
   close the ways a record could carry text that no record hash covers. None of these
   checks changes a preimage byte. The section 2 encoding is unambiguous over
   decoded values, and these checks only decide which documents decode.
2. A record whose `event_kind` has no schema in this document is a hard failure
   at that index (`unknown_kind`). It is never skipped. So is an `interaction`
   whose `features_canonical` array does not hold exactly 27 elements
   (`feature_arity`; a NULL there fails rule 1 instead), and any record whose
   preimage exceeds the section 2.1 per-preimage bound (`over_limit`).

   A token outside a section 4.7 vocabulary, other than an `event_kind`, is
   **not** a failure. Those vocabularies grow when an enum gains a variant, which
   changes no field list and no field type and so needs no tag bump. A verifier
   that rejected unknown tokens would reject valid future records. An
   `event_kind` is the exception because it selects the field table: a kind with
   no schema cannot be decoded, which is the hard failure above, and a new kind is
   a new tag (section 2.2).

   If a verifier does not recognise a `gate_decision` record's (`verdict`,
   `decision`) pair, because a value is outside the section 4.7 vocabulary or
   because the pair is not one section 4.4.1 lists, it MUST NOT count or present
   that record as an allow (section 4.4.1), and SHOULD report the record with its
   raw `verdict` and `decision`. A record that verifies is intact; that says
   nothing about whether an unrecognised pair delivered the held call. Raw means
   as stored, not mapped to a known token.

   A verifier MUST escape every string a document carries before showing it to a
   person, so that a document cannot forge or hide the verifier's own output.
3. Recompute the preimage from the record's own fields, `SHA256` it, and compare
   to the stored hash, the record's `hash` member (`hash_mismatch`).
4. Check `prev_hash` equals the **stored** hash of the record before it in the
   walk, the record with the next lower `seq` (`link_break`). Where several
   records carry that `seq`, the link holds if it equals the stored hash of any of
   them. A record at the lowest `seq` has no record before it, and rule 4 does not
   apply to it: at `seq` 0 its link to the genesis is a chain check, below.

A failure of any of rules 1 to 4 makes the chain `broken`.

Then the chain as a whole:

- `seq` MUST be unique. A `seq` that two records carry makes the chain `broken`
  (`duplicate_seq`). It is not also a gap.
- With at least one record in the walk, the walk MUST start at `seq` 0. A lowest
  `seq` other than 0, a negative one included, is `root_missing`. When it is 0,
  every record at `seq` 0 MUST be a `chain_upgrade` (`root_not_chain_upgrade`)
  whose `prev_hash` equals the document's `genesis` (`root_genesis_mismatch`).
  Each of these failures makes the chain `truncated`, never `verified`.
- Between consecutive distinct `seq` values of the walk, `seq` MUST increase by
  exactly 1. A step of more than 1 is a gap, and makes the chain `truncated`
  (`seq_gap`). A gap whose links hold, the record after it linked to the record
  before it, is `truncated` and nothing more. A record deleted from the middle of
  a chain leaves the record after the hole linked to the deleted record, which
  rule 4 fails, so such a deletion is `broken`. Record 0 deleted is
  `root_missing`, and the last record deleted shows only against the anchor.
- The carried anchor, checked against the records:
  - an `entry_count` above the record count makes the chain `truncated`
    (`anchor_exceeds_records`). With zero records, that is any `entry_count`
    above 0;
  - otherwise, with `entry_count` above 0 and a `head_hash`, `head_hash` MUST
    equal the stored hash of the record at position `entry_count - 1` of the walk,
    counting from 0, or, where several records carry that record's `seq`, of one
    of them. A `head_hash` that differs makes the chain `broken`
    (`anchor_head_mismatch`). One that matches while `entry_count` is below the
    record count leaves an unanchored tail: the verdict stands, and the verifier
    MUST report an unanchored tail of N records, N being the record count less
    `entry_count`;
  - with `entry_count` above 0 and no `head_hash`, the head check is not made, and
    the verdict stands;
  - otherwise, with no anchor, or with an `entry_count` of 0 while records are
    present, the verdict stands, and the verifier MUST report that truncation of
    the chain's tail cannot be detected from this document. With no anchor it
    MUST also report which kind, by its code: `anchor_absent`, `anchor_null` or
    `anchor_unreadable`. With zero records and an `entry_count` of 0, the verdict
    is `empty` and nothing more is reported.
- A document with zero records reports `empty`, never `verified`, unless its
  anchor counts records it does not hold (above).
- In a store, rows carrying `chain_version = 1` are not part of the 2.0 chain and
  are not walked. They are verified, if at all, as a 1.0 document in link-only
  mode. A document's records carry no such member: a `chain_version` member fails
  rule 1.

The chain checks are made whatever rules 1 to 4 find, and each finding is
reported with its code. They read a record's `seq` only where it is an integer,
and its `event_kind`, `prev_hash` and `hash` only where each is a string: a
value that fails rule 1 is reported there and not again, and a record with no
integer `seq` has no place in the walk. The verdict is `broken` if any finding
makes the chain `broken`, otherwise `truncated` if any makes it `truncated`,
otherwise `empty` for zero records and `verified` for any.

**The carried anchor and genesis are self-asserted.** No record hash covers
either (section 9), and whoever writes a document writes both. The checks above
catch a document that is inconsistent with itself: records deleted, cut or
replaced while the carried values were left as they were. They do not catch a
document rewritten whole, its records re-linked from its genesis and its anchor
rewritten to match. Section 6 compares the device's store with its keychain, and
it does not apply to a document.

The walk advances from the **stored** hash, so a break does not cascade. The
reported index bounds the break rather than naming the culprit: a record altered
and re-hashed reports at the following index, and a deletion reports at the
record after the hole. The verifier says "break at or before index N", not
"record N was tampered".

A 2.x verifier reading a 1.0 document verifies linkage only and states that
content was not covered. A 1.0 verdict never asserts content integrity, and
never matches a 2.x verdict: a verifier MUST NOT report a 1.0 document, in any
output, with a verdict a 2.x document can also receive.

A document that fails the parse check (`invalid_json`, `duplicate_member`), the
format check (`unrecognised_format`, `format_mismatch`) or the document member
check (`missing_member`, `malformed_member`) is `rejected`: none of its records is
walked, and it gets no other verdict and reports no other code, an anchor code
included. `rejected` is given before any walk and
asserts nothing about either format; the rule above governs the verdicts of a
walk. Every code this section gives, and the verdict it carries:

| Code | Check | Verdict |
| --- | --- | --- |
| `invalid_json` | the text is not one JSON value | `rejected` |
| `duplicate_member` | an object, at any depth, repeats a member name | `rejected` |
| `unrecognised_format` | no declared version this section recognises | `rejected` |
| `format_mismatch` | a 1.x declaration on structure only 2.x defines | `rejected` |
| `missing_member` | a 2.x document without `records`, or with a record count of 1 or more and without `genesis` | `rejected` |
| `malformed_member` | `records` not an array, or, with a record count of 1 or more, `genesis` not a string | `rejected` |
| `unknown_member` | rule 1: a member outside the record's fields | `broken` |
| `missing_field` | rule 1: a member that is missing | `broken` |
| `wrong_type` | rule 1: a record that is not an object, or a value not of its declared type | `broken` |
| `null_field` | rule 1: a NULL where none is allowed | `broken` |
| `null_element` | rule 1: a NULL array element | `broken` |
| `over_limit` | rule 1: a length or count header above a limit; rule 2: a preimage above the limit | `broken` |
| `unknown_kind` | rule 2: an `event_kind` with no schema | `broken` |
| `feature_arity` | rule 2: `features_canonical` without exactly 27 elements | `broken` |
| `hash_mismatch` | rule 3: the recomputed hash is not the stored hash | `broken` |
| `link_break` | rule 4: `prev_hash` is not the stored hash before it | `broken` |
| `duplicate_seq` | a `seq` two records carry | `broken` |
| `anchor_head_mismatch` | `head_hash` is not the stored hash at position `entry_count - 1` | `broken` |
| `root_missing` | the lowest `seq` is not 0 | `truncated` |
| `root_not_chain_upgrade` | the record at `seq` 0 is not a `chain_upgrade` | `truncated` |
| `root_genesis_mismatch` | the record at `seq` 0 does not link to the `genesis` | `truncated` |
| `seq_gap` | `seq` skips a value | `truncated` |
| `anchor_exceeds_records` | `entry_count` above the record count | `truncated` |
| `anchor_absent` | a walked 2.x document has no `anchor` member | none (informational) |
| `anchor_null` | a walked 2.x document's `anchor` is `null` | none (informational) |
| `anchor_unreadable` | a walked 2.x document's `anchor` is present, not `null`, and holds no `entry_count` that can be read | none (informational) |

### 7.1 Versioning the `gate_decision` vocabulary

Adding a row to section 4.4.1, a new `decision` value or a new pair of existing
values, is a minor change. Removing a row, or changing the meaning of one, is a
major change. A row's meaning is what section 4.4.1 says of it and whatever else
section 4 says of its values, and a release that adds a value adds its row there.
This governs the spec's release version, not the format tag: section 2.2 alone
decides when the tag changes, and neither kind of change touches a field list, a
field order or a field type. A major release under this section does not re-root
the chain either; the section 5.1 pattern belongs to a new tag.

A release that changes no preimage byte is also minor when the only documents it
newly fails, documents it rejects or reports `broken` or `truncated` where an
earlier release did not, repeat a member name (RFC 7493 section 2.3), have
records that carry members or content no record hash covers, or break a rule an
earlier release already stated, the 1.0 schema included, that its reference
verifier did not enforce. A top-level member a verifier does not read stays
outside every hash, so it is not a ground for rejection. A repeated member name
is, at the top level as at any depth: of two `records` members a parser keeps
one, and the other carries a copy of the chain that no check reads.

Spec release 2.1.0 is such a release, except for two kinds of document, below.
It fails a
repeated member name. It fails a member outside the record's fields, the
vectors-file directive in a document and a `hash` that is not a string, each text
no record hash covers. It fails these, each a rule already stated: a NULL the
section 4 tables forbade; a missing field, which 2.0.0's rule 1 already failed (a
field that is absent does not decode); a document that declares 1.x and carries
structure only 2.x defines (a `records` member, or an entry carrying
`event_kind`, `seq` or `timestamp_us`), and a 1.0 array of entries in which an
entry does not declare 1.x, neither of which the 1.0 schema allows; a repeated
`seq`, which 2.0.0 already forbade (section 4.0 made `seq` unique and gapless, and
section 7 made it increase by exactly 1) without naming a verdict; and a
carried anchor whose `head_hash` is not the stored hash of the record it counts
to, which is what 2.0.0's section 6 defined `head_hash` to be.

The two kinds are documents 2.0.0 did not fail: it named neither `records` nor
`voaf_version`, and left the document members to the unpublished document
format. They are a 2.x document without a `records` array, and a document
without a declared version section 7 recognises. 2.1.0 rejects both, and no 2.0
producer emitted either: Vigil 2.3.2 writes `voaf_version` `2.0` and a `records`
array in every 2.0 export. A document with a record count of 1 or more and no
genesis string is rejected too, but 2.0.0, which rooted record 0 at the genesis,
could not verify it either. With a record count of 0 the genesis is not read, so
Vigil 2.3.2's export of a store with no records and no genesis, which carries
`"genesis": null`, reports `empty`, or `truncated` when its anchor counts
records, as it did under 2.0.0 (`doc_empty_store_genesis_null`). Every document
a 2.0 producer emitted from an intact store still verifies under 2.1.0, or, with
zero records, still reports `empty`: a real export from Vigil 2.3.2 does.

**Erratum.** 2.0.0 said, in section 4.4, that the `client_disconnected` outcome
is exactly the case of "a hold whose client left mid-hold", which "delivered no
bytes". Both were broader than any producer wrote it: a producer records
`client_disconnected` only when it finds the client gone, and on a streamed
response the events before the held call may already have been delivered.
Revision 4 corrects the text; the value's meaning, that nothing was delivered for
the held call, is unchanged, and no producer wrote a record the corrected text
does not describe. The rule above governs every release after 2.1.0.

Rule 2 is what makes an added value or pair safe for a verifier that predates
it: that verifier still verifies the record. A verifier written to revision 4 or
later is also bound by the rule 2 addition: it does not read an unrecognised pair
as an allow, and it should report it. A 2.0.0 verifier is bound only by rule 2
itself.

## 8. Acceptance

1. Historical, from revision 3, about Vigil's writer: `chain::preimage(&Record)
   -> Vec<u8>` is the single implementation. The three hand-rolled copies at
   `vigil-store/src/lib.rs:468-475`, `:1040-1045` and `:1382-1386` are replaced
   by calls to it.
2. Every vector in `spec/2.0/test-vectors.json` reproduces byte for byte in Rust,
   against both `preimage_hex` where present and `preimage_sha256` always.
3. A Python hasher under 150 lines, written by C-verify from this document
   alone, reproduces every positive vector hash without reading the Rust. The
   criterion measures a hasher: the section 2 encoding over the section 4 tables.
   The budget is 150 rather than 100 because a from-prose implementation measured
   98 lines only under deliberately dense formatting and about 135 naturally. The
   point of the budget is that the hasher stays auditable by eye, not that it hits
   a round number. A full verifier, which also makes the section 7 checks, is
   longer and is not held to the budget. Not met for spec release 2.1.0: no hasher
   written from the prose is published. The reference verifier,
   `spec/2.0/reference-verifier.rs`, is not written from the prose and does not
   meet this criterion.
4. **Altering any field value, the format tag, or the field count changes the
   hash.** Field types are fixed per tag by the section 4 tables; a type change
   is a tag bump, not something the encoding detects.
5. `interaction_empty_vs_null` differs from `interaction_minimal`;
   `gate_decision_empty_array_vs_empty_string` differs from the same record with
   **`rule_ids`** retyped to an empty string (that vector has two empty arrays,
   and substituting `snapshot_ids` instead gives a third, different hash);
   `interaction_content_off` differs from `interaction_minimal`.
6. A verifier hard-fails a `u32be` length header above 2^20 and an array count
   header above 2^16. The `negative_vectors` array in the companion vectors file
   carries a case for each, alongside the tag-mutation and field-count-mutation
   cases that exercise criterion 4; these revision 3 cases name no `violation`.
   From revision 4 it also carries a case for the section 7 parse check, for the
   2.x-structure check, and for each section 7 rule 1 check without which a
   record could verify, each naming the `violation` it must produce; a decision
   edited without re-hashing, which rule 3 fails; and a nullable field left out,
   which 2.0.0's rule 1 already failed and its reference verifier already
   rejected. Three of the rule 1 cases, `neg_field_over_limit`,
   `neg_held_ms_string` and `neg_id_null`, are checks the v2.0.0 reference
   verifier also made. The `negative_documents` array carries thirteen whole
   documents for the chain and document checks and the informational anchor
   codes, each naming its verdict and codes. The checks that a record is an
   object, that `event_kind` and `hash` are present and not NULL, and that
   `event_kind` is a string, have no case: without them a verifier cannot decode
   the record, pick a table or compare a hash, so it rejects the record anyway.
   Each case's `stored_hash` is what a reader without its check computes, and
   section 8.1 says which reader that is. Vigil's own 2.0 verifier reports the
   relabel case verified.
7. The exporter emits every preimage input for every record. Criteria 2 and 3
   pass against a document produced by the shipped exporter, not only against the
   checked-in vectors.

### 8.1 The companion vectors file

Acceptance criterion 3 asks for a hasher written from this document alone, and a
verifier can be written the same way, so every member of
`spec/2.0/test-vectors.json` that an implementation reads is specified here, and
the rest are marked informative.

| Field | Meaning |
| --- | --- |
| `vectors[].name`, `negative_vectors[].name` | The vector's name, which `basis` and the prose cite |
| `vectors[].record` | The record's fields, keyed by the names in section 4. It carries `event_kind`, equal to `vectors[].event_kind`, and no `hash`. The only place a loader expands the section 4.2.1 directive, before decoding |
| `vectors[].event_kind` | The kind, selecting the section 4 table |
| `vectors[].expected_hash` | `SHA256` of the preimage, and the record's stored hash in the chain walk |
| `vectors[].preimage_sha256` | `SHA256` of the preimage bytes, always present |
| `vectors[].preimage_len` | Byte length of the assembled preimage |
| `vectors[].preimage_hex` | The preimage bytes, lowercase hex. **Null** when the preimage exceeds 4096 bytes; check `preimage_sha256` instead |
| `vectors[].chain_member` | Whether this vector is part of the linked chain |
| `vectors[].note` | Informative prose about the vector. Not normative |
| `vectors[].must_differ`, `vectors[].substituted_field`, `vectors[].expected_hash_if_rule_ids_were_empty_string` | Acceptance criterion 5: the hash the record would have with `substituted_field` encoded as an empty string instead of an empty array, which must differ from `expected_hash` |
| `genesis.cases[].install_nonce_hex`, `genesis.cases[].expected_genesis` | The 32 raw nonce bytes as hex, and the section 5 genesis computed from them |
| `chain.genesis_case_index` | Index into `genesis.cases` of the nonce anchoring the chain |
| `chain.head_hash`, `chain.entry_count` | The walk's expected head and length |
| `field_counts` | The section 2.2 table |
| `negative_vectors[]` | Inputs that must not verify, or mutations whose hash must move |
| `negative_vectors[].basis` | The positive vector the case is derived from |
| `negative_vectors[].mutation` | In prose, what was changed from `basis`. On a vector with no `record`, `record_json` or `document`, it is the whole input: apply it to the basis |
| `negative_vectors[].expected_hash`, `negative_vectors[].must_differ_from` | On a mutation case, the hash of the mutated preimage, and the basis hash it must differ from. On `neg_decision_edited_without_rehash`, what recompute gives |
| `negative_vectors[].expected_outcome`, `negative_vectors[].requirement` | In prose, how the case fails and the rule it exercises |
| `negative_vectors[].record` | Present from revision 4: a whole record exactly as a document carries it, `event_kind` and `hash` included, never expanded, that must fail section 7 at that record. In it, an object shaped like the section 4.2.1 directive is a literal value |
| `negative_vectors[].record_json` | Present from revision 4: a record as JSON text, for a case a parsed object cannot hold. It fails the section 7 parse check |
| `negative_vectors[].document` | Present from revision 4: a whole document, for a check made before any record. `neg_relabelled_1_0` fails the section 7 format check (`format_mismatch`) |
| `negative_vectors[].violation` | Present from revision 4 on every vector that carries `record`, `record_json` or `document`: the check it fails, by the code section 7 gives it. Used here: `duplicate_member`, `format_mismatch`, `unknown_member`, `missing_field`, `wrong_type`, `null_field`, `null_element`, `over_limit` and `hash_mismatch`. Section 7 lists every code |
| `negative_vectors[].acceptable_violations` | Present where a verifier that lacks the vector's check still rejects it at another: every code a verifier may then report. `violation` is the vector's own check, the one the reference verifier produces |
| `negative_vectors[].stored_hash` | The hash the record's `hash` member carries. In `neg_decision_edited_without_rehash`, `expected_hash` is what recompute gives instead, so rule 3 fails. In every other vector it is what a reader without the failing check computes: for a repeated name, a parser that keeps the last copy (`neg_duplicate_member`) or the first (`neg_duplicate_member_mirror`); for a missing field, a reader that takes it as NULL; for a non-string `hash`, the v2.0.0 reference verifier, which never reads it; for a field over a limit, a reader that writes the header it finds; for a string in an integer field, a reader that takes the marker from the declared type; for a NULL envelope field, a reader that writes the NULL marker; otherwise the v2.0.0 reference verifier. So only that check rejects the record, except where `acceptable_violations` names a second |
| `negative_documents[]` | Present from revision 4: whole documents that do not verify cleanly, for the chain checks, the document checks and the informational anchor codes of section 7. Each fails a check, or reports `empty`, or verifies only with an informational code |
| `negative_documents[].name`, `negative_documents[].mutation`, `negative_documents[].expected_outcome`, `negative_documents[].requirement` | The case's name; in prose, the document and what was changed in it; its verdict and why; and the rule it exercises |
| `negative_documents[].document` | The document, as a verifier reads it. Its records are written as a document carries them, `event_kind` and `hash` included, and never expanded |
| `negative_documents[].document_json` | The document as JSON text, for a case a parsed object cannot hold |
| `negative_documents[].expected_verdict` | The section 7 verdict |
| `negative_documents[].expected_codes` | Every code a verifier that makes every section 7 check reports for the document, informational codes included, each once, in no particular order. No negative document holds a record that fails rule 1, 2 or 3 |
| `spec`, `revision`, `supersedes`, `generated_for`, `revision_4`, `hash`, `markers`, `limits`, `repeat_directive`, `feature_slots`, `genesis.construction`, `genesis.cases[].note`, `chain.note`, `chain.membership` | Informative: this file's history, and restatements of sections 2, 2.1, 3 and 4.2.1. `limits.max_content_bytes` is the section 2.1 per-field limit, which applies to every string and integer field, not content only |

`neg_tag_mutated` writes the tag `voaf-2.1` only to show that the hash moves
with the tag. Spec release 2.1.0 keeps the tag `voaf-2.0` (section 2.2).

**Chain membership is `chain_member`, not prose.** Walk exactly the vectors
where it is true, in `seq` order. An earlier revision expressed membership only
as an English sentence in `chain.note` and a new vector was added without
updating it, which broke the walk for every following record. A flag cannot go
stale the same way.

`chain.entry_count` describes this file's own chain and must equal the walk
length exactly. It is not a live keychain anchor and the section 6 lagging-tail
allowance does not apply to it.

## 9. What the hash does not cover

Stated here because the format exists for regulatory review and an overclaim is
the failure this feature exists to prevent.

- **There is no trusted time.** `timestamp_us` is the device's own wall clock at
  write time: unsynchronised, non-monotonic across a clock change, and settable
  by anyone controlling the machine. The chain proves order, not time. The format
  leaves room to fix this: publishing the head hash to a third party or a
  timestamping authority on a schedule would anchor time externally. Parked for
  2.4.
- **The chain is unkeyed and the export is unsigned.** An off-device verifier
  cannot distinguish a genuine export from a hand-written one. The section 6
  anchor in the device's keychain is the only truncation detection that does not
  rest on the document. The anchor and genesis a document carries are
  self-asserted: section 7's checks against them catch a document inconsistent
  with itself, not one rewritten whole.
- **Provenance is not established.** `POST /api/ingest` is auth-exempt and
  cross-origin-exempt by design, so a record's presence does not prove Vigil
  observed the traffic it describes.
- **Content is hashed as stored**, capped at 2^20 bytes per field with truncation
  recorded in the record. Before C.2, capture truncated at 500 characters and
  appended a literal three-character ellipsis, so v1 rows hold at most 503
  characters and nothing in a v1 record marks that truncation occurred.
- **`gate_decision` response hashes are self-attestation.** They record what the
  producer had received and what it had written, or was writing, to the client,
  not what a client received, and no third party can reproduce them. On
  (`allow`, `restore`) they are digests of files, which a holder of the file can
  reproduce.
- **Members outside the records are covered by no hash.** The declared format,
  the genesis, the anchor and any exporter metadata travel with the document. A
  verifier reads the first three as section 7 says and ignores the rest. Section 7
  checks the records against the carried genesis and anchor, which catches a
  document inconsistent with itself, not one rewritten whole. The document's
  top-level members stay outside every hash.
- **Keychain items are software-protected** by an ACL bound to the sidecar's
  signing identity. They are not hardware-bound. No document may say otherwise.
- **`encryption_at_rest` describes the store.** An exported document written to
  `~/Downloads` is plaintext.
- **Outside the chain:** `intent_vector`, `features_json` as a cache, the
  `timestamp TEXT` display column, and every side table that is not chained
  (`alerts`, `policies`, `baselines`, `meta`, `repair_events`, `execution_gates`,
  `trust_scores`, and `vault_entries` in `vigil_vault.db`). Deleting rows from
  any of these is undetectable by chain verification.

## Appendix A. Known producer deviations

Non-normative. Where a Vigil release does not meet a definition in sections 4.4,
4.4.1 or 4.7.1, or leaves a decision with no record. A.1 to A.3 are Vigil 2.3.2;
A.4 is Vigil 2.3.0 and 2.3.1. A verifier reads a record by those definitions, not
by this list; the list says where Vigil's records and the definitions part.

### A.1 The shutdown drain race

The flag check and the queue are not one step. `hold()` reads the shutting-down
flag without the queue's lock (`vigil-proxy/src/hold_queue.rs:137`), then takes
the lock and inserts the hold (`:151-158`), while `shutdown()` sets the flag and
drains the queue under that lock (`:237-240`). A hold that read the flag before it
was set, and is inserted after the drain, is neither denied nor refused, and it is
never recorded as `shutdown_deny`. It ends as `timeout_deny` if its hold window
passes before the process exits, as `client_disconnected` or
`connection_panicked`, as a person's decision only through a decide request the
producer had already accepted when it stopped accepting them (an approve then
delivers the call during shutdown), or, with the default 30-second window, most
often with no record at all, because the process exits first. A record it does
get can follow the `lifecycle` `shutdown` record. The absence of a `shutdown_deny`
record is therefore not evidence that no hold was open at shutdown.

### A.2 An allow pair for a call never released

Vigil 2.3.2 writes an allow pair, (`allow`, `allow`), (`hold`, `user_approve`) or
(`hold`, `always_allow`), with a present `response_hash_delivered`, for a call it
never released, in two cases:

- A call behind a `client_disconnected` call in the same response: on Anthropic
  streams, a call after it; on OpenAI and Google streams, any call in the same
  group, including calls approved and recorded before the disconnect. The
  disconnected call is never resolved, so nothing waiting on it is released, and
  the stream ends with those calls dropped. Later records on that stream also
  carry a present `response_hash_delivered` for a client known to be gone.
- An approved buffered body that the producer's repair step then replaces (its
  block arm) or alters (its redact arm) before it is forwarded.

Those records do not meet the section 4.4.1 definition of delivered or the
section 4.4 NULL rule.

### A.3 Holds and calls that leave no record

In Vigil 2.3.2 each of these leaves no `gate_decision` record of any kind. They
are every loss path found by reading the source at `c449787`; the list is not
proven complete.

- any decision whose write to the store fails without a panic, the
  `connection_panicked` flush included: it is logged as an audit gap and no row is
  written;
- a hold already resolved but not yet recorded when its connection task panics,
  whether a decide request, the hold window, a failed keepalive or the shutdown
  drain resolved it;
- a hold decided by a decide request, or drained by shutdown, after the task
  panics and before the supervisor's flush;
- a hold parked outside a connection task, which the flush never reaches, and a
  hold whose own record panics while it is flushed;
- a hold refused because shutdown had begun, if its task panics before it records
  it: a refused hold was never in the queue, so the flush cannot find it;
- a `shutdown_deny` the task has not recorded when the process exits;
- a hold raised for a tool call that only a trailing, unterminated SSE frame
  completes: the gate drops the call and records nothing;
- a hold that escaped the shutdown drain (A.1), when the process exits first.

Where a decide request made the decision, the request was answered with success.

### A.4 Vigil 2.3.0 and 2.3.1: producer denials recorded as `user_deny`

Vigil 2.3.0 (`ac2be27`) and 2.3.1 (`4eb912b`) predate `shutdown_deny`. Three
denials the producer made on its own authority are recorded as (`hold`,
`user_deny`), the pair section 4.4.1 gives to a person's deny:

- the shutdown drain, which sends a deny to every open hold
  (`vigil-proxy/src/hold_queue.rs:216` in both releases);
- a hold refused because shutdown had begun (`proxy.rs:1338` and `:1962`);
- a closed decision channel (`proxy.rs:2539` and `:2577`).

`decision_str` maps all three to `user_deny` (`proxy.rs:2637`). A `user_deny`
record from those releases does not prove that a person decided. Vigil 2.3.2
records the first two as `shutdown_deny`, and maps a closed channel to
`shutdown_deny` too (`proxy.rs:2793` and `:2835` at `c449787`).

A reader cannot reliably tell which release wrote a record. A Vigil 2.0 document
carries no producer version: its members are `voaf_version`, `tag`,
`generated_at`, `encryption_at_rest`, `genesis`, `head`, `anchor`, `predecessor`
and `records`. The one version in the chain is `app_version` on a `lifecycle`
`shutdown` record, which a release writes only when it shuts down gracefully. It
does not attribute the records around it: a process that crashed writes none, and
a denial recorded during the shutdown drain can follow it. So in a chain that
Vigil 2.3.0 or 2.3.1 may have written, a `user_deny` record cannot be told apart
from a person's deny.

## Appendix B. Vigil 2.3.2 producer notes

Non-normative. How Vigil 2.3.2 writes the records sections 4.4, 4.4.1 and 4.7.1
define, where it meets them.

- `shutdown_deny` and `connection_panicked` come from `decision_str` and
  `record_orphaned_hold` in `vigil-proxy/src/proxy.rs`. `interaction_id` is NULL
  on every `gate_decision` record, whatever the decision.
- `actor` is the constant `vigil-gate` on every record, whoever decided. The
  pair, not `actor`, says who decided.
- A person decides from the tray (approve, deny) or the dashboard (approve,
  deny, always allow), both through the token-guarded local API, which any local
  process holding the token can also call. A restore has no tray or dashboard
  control and runs through that API only.
- (`hold`, `allow`) is written only when the gate policy's `gate_enabled` is
  false.
- (`allow`, `allow`) and (`hold`, `allow`) are written only on a streamed
  response, at its final chunk, with hashes over the whole response. An allowed
  or observe-only call on a buffered response, or on a stream cut before its
  final chunk, has no record, so the absence of a `gate_decision` record is not
  evidence that no tool call was made. Section 4 does not require a record for
  every call.
- `always_allow` writes its allowlist entry before the decision is delivered. An
  entry can therefore exist with no `always_allow` record: after a decide request
  answered 404, or one answered with success whose decision then lost to the hold
  window or a client disconnect. A later call the entry covers is recorded as
  (`allow`, `allow`) on a streamed response, with empty `rule_ids` and nothing
  linking it to the entry, and has no record on a buffered one. The allowlist is
  not chained.
- `client_disconnected` is written only on a streamed response, when the
  producer's keepalive write to the client fails during the hold
  (`vigil-proxy/src/proxy.rs:2798-2801`; one write every 10 seconds, the first 10
  seconds into the hold). A buffered response has no such check. A client that
  leaves before the first keepalive, or after the last, is recorded under the
  decision the hold reached.
- On a buffered response the hold records are written before the body is
  forwarded to the client (`proxy.rs:2226-2233`, then `:2298-2323`), and a forward
  that then fails is only logged (`:2324-2326`).
- A hold record's hashes cover the response up to the moment the hold resolved.
  The OpenAI and Google adapters and the Anthropic buffered adapter release a
  message's calls together; the Anthropic stream adapter releases them from the
  front. So a hold resolved while a call it waits on is undecided records a
  `response_hash_delivered` over output that excludes its own call: on a buffered
  response, the SHA-256 of empty input. That meets section 4.4.
- Timeout deny text names the hold window. When another call in the same message
  was denied, a released call can be re-serialized rather than byte-identical. A
  streamed write to the client is not checked.
- `held_ms` is counted in whole seconds, times 1000, and `timestamp_us` is the
  time the record was written, not the time of the decision: for (`allow`,
  `allow`) and (`hold`, `allow`), the end of the stream.
- A decide request answered with success is not proof of the recorded outcome. A
  decision that races the hold window, a failed keepalive write or the connection
  task's own resolution can be acknowledged and then lost, and the record carries
  the outcome the task took.
