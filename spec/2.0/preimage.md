# VOAF 2.0 preimage

Revision 4, spec release 2.1.0. Status: proposed, frozen on acceptance. Owner: C-store.
Companion vectors: `docs/specs/voaf-2.0-test-vectors.json` (revision 4).
Companion document format: `voaf-2.0-document.md`, owned by C-verify.
Supersedes the Hash Computation section of `docs/VOAF_SPEC.md`.

This document defines the exact bytes hashed for every chained record, and
nothing else. The JSON envelope that carries those records is specified in the
companion document. Nothing in Track C may define or vary the preimage.

### Revision history

Revision 1 was rejected by adversarial review with three proven collision
classes: empty scalar and empty array encoded identically, integer and string of
the same digits encoded identically, and an array could bleed across a differing
field count to produce a byte-identical preimage carrying different real
content. Revision 2 closed all three with typed markers and additionally typed
the NULL marker. Revision 3 reverts the typed NULL per owner ruling, adds
content length and the re-rooted chain, and states the limits.

Revision 1 and 2 vectors are withdrawn, not amended.

Revision 4 is spec release 2.1.0. It changes no preimage byte and no field, so
the format tag stays `voaf-2.0`. It adds two `gate_decision.decision` tokens
(section 4.7.1), states how a verifier treats a decision it does not recognise
and how that vocabulary is versioned (section 7), makes the reference verifier
reject a NULL `decision`, and adds six positive and two negative vectors. Every
revision 3 vector, and the chain, is unchanged.

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

The version is 2.0, not 1.1, because `docs/VOAF_SPEC.md` Versioning Policy
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
declares 32 while encoding 33. That vector exists to show the hash moves when the
count is mutated, not to be accepted as a valid document.

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

#### 4.2.2 A body that is not valid UTF-8

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

#### 4.2.1 The repeat directive in test vectors

Two vectors carry content larger than is reasonable to check into a file. Where
a vector's value is the object

```
{"$repeat": {"char": "<single character>", "count": <integer>}}
```

it denotes that character repeated `count` times, encoded UTF-8, expanded before
hashing. "Character" means one Unicode scalar value. The **expanded** value is
subject to the section 2.1 limits exactly as a literal value would be. This is a property of the vector file, not of the preimage or of any
stored record. It is stated here because acceptance criterion 3 requires the
reference verifier to be written from this document alone, and without this
paragraph two vectors cannot be evaluated from it.

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

Inlined rather than referenced, because `docs/specs/execution-gate-v1.md` is not
on this branch. That file's section 10 is informative; this table is normative.

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

`response_hash_delivered` is NULL when nothing was delivered. The
`client_disconnected` and `connection_panicked` outcomes are exactly that case: a
hold whose client left mid-hold, or whose connection task failed while it was
held, delivered no bytes, and recording a delivery hash for it would assert a
delivery that did not happen. A verifier must not treat a NULL there as missing
data. `connection_panicked` also carries a NULL `response_hash_upstream`
(section 4.7.1).

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

### 4.7.1 `shutdown_deny` and `connection_panicked`

Added in revision 4, spec release 2.1.0. Each records a held call that no person
decided, and each is written with `verdict` = `hold`. Neither is a person's deny,
and neither is an allow.

**`shutdown_deny`**

- Written by: the producer's gate, on its own authority.
- When: the producer is shutting down. Its shutdown sequence denies every open
  hold before the process exits, and a hold that arrives after shutdown has begun
  is denied as it is made.
- Whether the held action executed: no. The producer writes deny text to the
  client in place of the tool call, the same substitution it makes for
  `user_deny`, so the client never receives the call. `response_hash_upstream`
  and `response_hash_delivered` are both present, and they differ.

**`connection_panicked`**

- Written by: the producer's connection supervisor, not the gate's decision path.
- When: the task serving the client connection failed while the hold was still
  open and undecided. The supervisor removes the hold from the producer's queue,
  so no later decision can act on it, and records it.
- Whether the held action executed: no. The task that held the call and the
  client connection is gone. The call is never written to the client, and the
  client sees its connection close. `interaction_id`, `response_hash_upstream` and
  `response_hash_delivered` are NULL: the supervisor never held the response, and
  nothing was delivered.

"Did not execute" is the producer's account of what it delivered, the same
self-attestation section 9 describes for the response hashes. No record can show
what a client did with a call it obtained some other way.

In Vigil 2.3.2 the two values come from `decision_str` and `record_orphaned_hold`
in `vigil-proxy/src/proxy.rs`.

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
`shutdown` record commits, so the anchor and the chain head are the same event
and a clean quit can never leave the anchor lagging.

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

The genesis is carried in no record. A verifier obtains it from the document
metadata block, which the companion document spec defines.

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
**Nothing is deleted.** This is the pattern for every future major version.

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

For each record in `seq` order:

1. Decode every field into its declared type. A field that does not decode, that
   violates its declared nullability, or whose `u32be` length or count header
   exceeds a section 2.1 limit, is a hard failure at that index. This check is on
   the header, never on the value of a `_length` field.
2. A record whose `event_kind` has no schema in this document is a hard failure
   at that index. It is never skipped. So is an `interaction` whose
   `features_canonical` does not hold exactly 27 elements, and any record whose
   preimage exceeds the section 2.1 per-preimage bound.

   A token outside a section 4.7 vocabulary is **not** a failure. Those
   vocabularies grow when an enum gains a variant, which changes no field list and
   no field type and so needs no tag bump. A verifier that rejected unknown tokens
   would reject valid future records.

   A verifier MUST NOT count or present a `gate_decision` record whose `decision`
   it does not recognise as an allow, and SHOULD report such records with the raw
   `decision` value. A record that verifies is intact; that says nothing about
   whether an unrecognised decision delivered the held call.
3. Recompute the preimage from the record's own fields, `SHA256` it, and compare
   to the stored hash.
4. Check `prev_hash` equals the previous record's **stored** hash.

Additionally:

- Record at `seq` 0 MUST be a `chain_upgrade` whose `prev_hash` equals the
  section 5 genesis. Otherwise the chain is `truncated`, never `verified`.
- `seq` MUST increase by exactly 1 between consecutive records. A gap is
  `truncated`.
- A document with zero records reports `empty`. Never `verified`.
- A document whose carried anchor `entry_count` exceeds its record count reports
  `truncated`.
- Rows carrying `chain_version = 1` are not part of the 2.0 chain and are not
  walked. They are verified, if at all, as a 1.0 document in link-only mode.

The walk advances from the **stored** hash, so a break does not cascade. The
reported index bounds the break rather than naming the culprit: a record altered
and re-hashed reports at the following index, and a deletion reports at the
record after the hole. The verifier says "break at or before index N", not
"record N was tampered".

A 2.x verifier reading a 1.0 document verifies linkage only and states that
content was not covered. It never reports such a document as `verified` without
that qualifier.

### 7.1 Versioning the `gate_decision.decision` vocabulary

Adding a `decision` value is a minor change. Removing one, or changing the meaning
of one, is a major change. This governs the spec's release version, not the
format tag: section 2.2 alone decides when the tag changes, and neither kind of
change touches a field list, a field order or a field type. Rule 2 is what makes
an added value safe for a verifier that predates it: that verifier still verifies
the record, and reports the value rather than reading it as an allow.

## 8. Acceptance

1. `chain::preimage(&Record) -> Vec<u8>` is the single implementation. The three
   hand-rolled copies at `vigil-store/src/lib.rs:468-475`, `:1040-1045` and
   `:1382-1386` are replaced by calls to it.
2. Every vector in `voaf-2.0-test-vectors.json` reproduces byte for byte in Rust,
   against both `preimage_hex` where present and `preimage_sha256` always.
3. A Python reference verifier under 150 lines, written by C-verify from this
   document and the companion document spec alone, reproduces every vector hash
   without reading the Rust. The budget is 150 rather than 100 because a
   from-prose implementation measured 98 lines only under deliberately dense
   formatting and about 135 naturally. The point of the budget is that the
   verifier stays auditable by eye, not that it hits a round number.
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
   cases that exercise criterion 4.
7. The exporter emits every preimage input for every record. Criteria 2 and 3
   pass against a document produced by the shipped exporter, not only against the
   checked-in vectors.

### 8.1 The companion vectors file

Acceptance criterion 3 says the reference verifier is written from this document
alone, so the fields of `voaf-2.0-test-vectors.json` are specified here rather
than left to be inferred.

| Field | Meaning |
| --- | --- |
| `vectors[].record` | The record's fields, keyed by the names in section 4 |
| `vectors[].event_kind` | The kind, selecting the section 4 table |
| `vectors[].expected_hash` | `SHA256` of the preimage, and the value section 7 rule 4 calls the stored hash |
| `vectors[].preimage_sha256` | `SHA256` of the preimage bytes, always present |
| `vectors[].preimage_len` | Byte length of the assembled preimage |
| `vectors[].preimage_hex` | The preimage bytes, lowercase hex. **Null** when the preimage exceeds 4096 bytes; check `preimage_sha256` instead |
| `vectors[].chain_member` | Whether this vector is part of the linked chain |
| `chain.genesis_case_index` | Index into `genesis.cases` of the nonce anchoring the chain |
| `chain.head_hash`, `chain.entry_count` | The walk's expected head and length |
| `negative_vectors[]` | Inputs that must not verify, or mutations whose hash must move |
| `negative_vectors[].record` | Present from revision 4: a whole record that must fail section 7 at that record. `neg_decision_null` fails rule 1 before any hash is computed |
| `negative_vectors[].stored_hash` | The hash a document carries for `record`. `expected_hash` is what recompute gives instead, so rule 3 fails |

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
  anchor is the only truncation detection and it lives on the device.
- **Provenance is not established.** `POST /api/ingest` is auth-exempt and
  cross-origin-exempt by design, so a record's presence does not prove Vigil
  observed the traffic it describes.
- **Content is hashed as stored**, capped at 2^20 bytes per field with truncation
  recorded in the record. Before C.2, capture truncated at 500 characters and
  appended a literal three-character ellipsis, so v1 rows hold at most 503
  characters and nothing in a v1 record marks that truncation occurred.
- **`gate_decision` response hashes are self-attestation.** The differing
  upstream and delivered hashes are Vigil's own account of two byte strings no
  third party can reproduce.
- **Keychain items are software-protected** by an ACL bound to the sidecar's
  signing identity. They are not hardware-bound. No document may say otherwise.
- **`encryption_at_rest` describes the store.** An exported document written to
  `~/Downloads` is plaintext.
- **Outside the chain:** `intent_vector`, `features_json` as a cache, the
  `timestamp TEXT` display column, and every side table that is not chained
  (`alerts`, `policies`, `baselines`, `meta`, `repair_events`, `execution_gates`,
  `trust_scores`, and `vault_entries` in `vigil_vault.db`). Deleting rows from
  any of these is undetectable by chain verification.
