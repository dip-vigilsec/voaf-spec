# NOTES: independent VOAF verifier, spec release 2.1.0 at voaf-spec commit 08f06db

## Sources

The only sources are the two spec files in this folder, now at voaf-spec commit
`08f06db`. I confirmed both hashes before changing anything:

| File | SHA-256 |
| --- | --- |
| `spec/2.0/preimage.md` | `16cf577108b8cc6208b18488c4e98212a24ca3be5f397725b32b9cf6f7a87262` |
| `spec/2.0/test-vectors.json` | `73f8ae9c31e310d560841ecb5292c4490cea28b0b9f76dd7ed673cb64d3372ef` |

Line numbers below are 1-based lines of this revision of `preimage.md`, unless
marked as vectors-file lines. Earlier line numbers in this file referred to the
previous text and have all been re-cited.

"VOAF 2.1" is spec release 2.1.0, and the format tag stays `voaf-2.0`:

- line 3: "Revision 4, spec release 2.1.0."
- lines 43-44: "It changes no preimage byte, no field and no hash, so the format
  tag stays `voaf-2.0`."

## Outcome

`run_vectors.py` passes every check:

- all 24 positive vectors;
- all 22 negative vectors;
- all 13 negative documents;
- the two genesis cases, the chain walk and `field_counts`;
- 18 derived checks for rules no vector covers.

Every negative document gives exactly its `expected_verdict`, and exactly its
`expected_codes` as a set, informational codes included (line 1252). I found no
vector whose normative outcome I disagree with. My disagreements, all with
informative text, are in section 3.

## 0. Where the new text decided something I had chosen differently

Each change below now follows the spec. "Old" is what the previous NOTES.md and
code did.

1. **The document's members.**
   - Old (2.1): pieced together from scattered mentions; the anchor shape was a
     guess; every other member ignored.
   - Now: lines 13-16 and 878-896 define `voaf_version`, `records`, `genesis`
     and `anchor`. Line 888 says "Every other top-level member is ignored, and so
     is every member of `anchor` but those two". The code reads exactly these.
2. **A 2.x document without a `records` array.**
   - Old (2.2): `unrecognised_format`.
   - Now: lines 890-894. No `records`, or `records: null`, is `missing_member`;
     a `records` that is not an array is `malformed_member`. Both are `rejected`
     (table, lines 1066-1067).
3. **No genesis.**
   - Old (2.6): `truncated` with my code `no_genesis`.
   - Now: lines 885 and 890-896. With one or more records, a missing or `null`
     genesis is `missing_member` and a non-string one is `malformed_member`, both
     `rejected`. "with a record count of 0 `genesis` is not read, whatever it
     holds" (lines 895-896). `no_genesis` is gone.
4. **A supplied genesis (`--genesis`, `--install-nonce`).**
   - Old (2.6): a supplied genesis took precedence over the document's.
   - Now: record 0 must link to "the document's `genesis`" (line 989; also lines
     738-739). The verdict follows the document. A supplied genesis that differs
     only adds a note.
5. **Which anchor rules apply to a document.**
   - Old (2.5): section 7 only by default, with the section 6 table available
     under `--anchor-table` (verdicts `unanchored` and `lost`).
   - Now: lines 798-800: "It does not apply to an exported document: section 7 is
     the complete set of checks a verifier makes on one, the anchor the document
     carries included". Lines 1038-1039 say the same.
   - `--anchor-table` is removed (it now exits 10 as an unknown option), and exit
     codes 4 and 5 are retired.
6. **An anchor head that differs.**
   - Old (2.5): a note by default; `truncated` (`anchor_head_mismatch`) or
     `broken` (`chain_replaced`) under `--anchor-table`.
   - Now: lines 1002-1006 and 1079. `anchor_head_mismatch` is `broken` whatever
     the counts. `chain_replaced` is gone.
7. **Reading `entry_count`.**
   - Old (2.5): only a canonical integer literal.
   - Now: lines 898-900: "a JSON number whose value is a non-negative integer, in
     any notation (`13`, `13.0` and `1.3e1` are one count, and a count of 2^64 or
     more exceeds every record count)". The parser keeps every number as its
     literal and reads the count exactly, never through a float.
8. **A head-less anchor with a readable count.**
   - Old (2.5): the whole anchor was "unreadable".
   - Now: `head_hash` is read "when it is a string" (lines 900-901). With an
     `entry_count` above 0 and no `head_hash`, "the head check is not made, and
     the verdict stands" (lines 1010-1011), but `anchor_exceeds_records` still
     applies.
9. **Absent, null and unreadable anchors.**
   - Old (2.5): notes only, with `"anchor": null` treated as absent.
   - Now: three informational codes, `anchor_absent`, `anchor_null` and
     `anchor_unreadable` (lines 902-909 and 1085-1087). Each changes no verdict
     and is reported as a code, together with the report "that truncation of the
     chain's tail cannot be detected from this document" (lines 1013-1016).
10. **Zero records with an anchor.**
    - Old (2.4): `truncated` by default, `lost` with `--anchor-table`; `empty`
      for an unreadable anchor.
    - Now: lines 999-1001 and 1018-1019. Any `entry_count` above 0 is
      `anchor_exceeds_records` (`truncated`), and `lost` is not a document
      verdict. With `entry_count` 0, "the verdict is `empty` and nothing more is
      reported" (lines 1016-1017). With no anchor it is `empty` plus the anchor's
      code (`doc_empty_store_genesis_null`).
11. **Recognising a declared version.**
    - Old (2.2): any digits-and-dots version whose first number, read as an
      integer, was 1 or 2. That accepted `01.0` as 1.x, which was a bug.
    - Now: lines 861-864. The first run must be exactly `1` or `2`, "`01` and
      `02` included" in what is not recognised.
12. **A repeated `seq`.**
    - Old (2.8): `duplicate_seq`, and rule 4 compared each record with its
      neighbour in the walk, so a second record at a `seq` could also give
      `link_break`.
    - Now: lines 984-985: "A `seq` that two records carry makes the chain
      `broken` (`duplicate_seq`). It is not also a gap." Rule 4 links to "the
      record with the next lower `seq`", and holds "if it equals the stored hash
      of any of them" (lines 974-977). The anchor head may match any record at
      the counted record's `seq` (lines 1003-1005).
13. **Record 0 checks.**
    - Old (2.8): only the first record of the walk was checked.
    - Now: "every record at `seq` 0 MUST be a `chain_upgrade`" (line 988), and
      each must link to the genesis (line 989). A negative lowest `seq` is
      `root_missing` (lines 986-987). The chain checks read `event_kind`,
      `prev_hash` and `hash` "only where each is a string" (lines 1026-1027), so
      a non-string `event_kind` at `seq` 0 no longer also gives
      `root_not_chain_upgrade`.
14. **Records whose `seq` does not decode.**
    - Old (2.8): the whole walk fell back to document order.
    - Now: "a record with no integer `seq` has no place in the walk" (lines
      1028-1029). Records are always walked in ascending `seq` order (lines
      915-916). Such a record's rule 1 findings carry no walk index; see 2.9.
15. **An empty top-level array.**
    - Old (2.2): `unrecognised_format`.
    - Now: line 867 rejects only "a top-level value that is neither an object
      nor an array of entries each declaring 1.x". An empty array vacuously
      qualifies, so I now walk it as a 1.0 document with no entries
      (`1.0-empty`). This is my reading of new wording; see 2.3.

These earlier choices are now stated by the spec, with no code change:

| Point | Spec lines |
| --- | --- |
| A NULL `hash` or `event_kind` is `null_field` | 936-938 |
| A record that is not an object, `null` included, is `wrong_type` | 920 |
| Precedence `broken` > `truncated` > `empty`/`verified` | 1029-1031 |
| A naive deletion is `broken`; a gap whose links hold is `truncated` | 991-997 |
| Repeated names are rejected at any depth, top level included | 850-855, 1105-1108 |
| `invalid_json` is the code for text that is not one JSON value | 855-856, 1062 |
| A rejected document reports one code and no anchor code | 1052-1056 |
| Rule-by-rule codes and verdicts | 1060-1087 |
| The 150-line budget measures a hasher, not a full verifier | 1170-1180 |
| An array of 1.0 entries where an entry does not declare 1.x is rejected | 1126-1127 |

## 1. Exit codes

The spec still defines none. Section 7 gives verdicts and codes (lines
1060-1087), but no process exit status. As instructed, 0 means `verified` and
everything else is non-zero:

| Exit | Verdict or condition |
| --- | --- |
| 0 | `verified`. An unanchored tail and informational anchor codes still exit 0 |
| 1 | `broken` |
| 2 | `truncated` |
| 3 | `empty` |
| 4, 5 | retired. They were `unanchored` and `lost`, which section 6 no longer gives a document (lines 798-800). The other codes keep their numbers |
| 6 | `rejected` |
| 7 | `1.0-linkage-only` |
| 8 | `1.0-link-broken` |
| 9 | `1.0-empty` |
| 10 | usage error, `--help`/`-h`, an unreadable input file, a bad `--install-nonce` |
| 11 | internal error, or a report that could not be written |

The 1.0 verdicts keep their own names and exit codes, because lines 1049-1050
say a verifier "MUST NOT report a 1.0 document, in any output, with a verdict a
2.x document can also receive". `rejected` is shared on purpose: lines 1056-1057
say "`rejected` is given before any walk and asserts nothing about either
format".

## 2. Ambiguities the new text still leaves

Each entry says what I did. Items the new text settled are listed as
**Resolved**, with the lines that settle them.

### 2.1 The 1.0 link-only walk (still open)

The 1.0 rules live in the README and in Vigil's `docs/VOAF_SPEC.md` (lines
17-19), and neither is in this folder. Lines 64-65 now say the reference
verifier "does not walk a 1.0 document". Line 876 still leaves the walk open:
"depending on its 1.0 walk".

`neg_relabelled_1_0.expected_outcome` describes Vigil's walk ("does not anchor
the first entry") and the README's ("anchors entry 0 to the all-zero hash"). I
kept the README walk because it is the stricter. The v1 hash (line 74) is not
recomputed, since line 1047 says "verifies linkage only". The entry member names
`prev_hash` and `hash` are an assumption, as is my code `malformed_entry` for an
entry lacking them.

### 2.2 The layout of a 1.0 object document (still open)

Section 7 defines only the 2.x members. For an object that declares 1.x, I
read its entries from `interactions`, the only layout any vector shows
(`neg_relabelled_1_0`). I reject one without an `interactions` array as
`unrecognised_format`, and I ignore an entry's own `voaf` member in that
layout.

The relabel list ("a `records` member or an entry carrying `event_kind`, `seq`
or `timestamp_us`", lines 871-872) is treated as exhaustive.

### 2.3 An empty top-level array (new)

Line 867 rejects "a top-level value that is neither an object nor an array of
entries each declaring 1.x". Line 1126 fails "a 1.0 array of entries in which an
entry does not declare 1.x". Neither says whether `[]` is a 1.0 document with no
entries or an undeclared document. I read it as the former (`1.0-empty`): no
entry fails to declare 1.x.

### 2.4 Comparing hashes, and the shape of hash-valued fields (still open)

- Line 216 says "rendered lowercase hex", and rule 3 compares "to the stored
  hash" (lines 972-973). I compare exact strings, so an uppercase stored `hash`
  is `hash_mismatch`.
- Lines 133-134: "A verifier does **not** validate the shape of a hash-valued
  field. A 63-character or uppercase digest verifies clean if it hashes clean".
  Against that, line 141 says such fields "are hashed as their 64 lowercase
  ASCII hex bytes", and line 278 types `prev_hash` as "string, 64 lowercase
  hex". I hash whatever string is present.
- Rule 4 "equals" (line 974), the genesis check (line 989) and the head check
  (line 1003) are all exact string comparisons.

### 2.5 Strings that do not decode, and the BOM (partly resolved)

- **Resolved:** a document whose bytes are not UTF-8 is not "one JSON value",
  so it is `invalid_json` (line 1062).
- **Still open:** line 129, "a value that does not decode is a verification
  failure at that index", names no code for a JSON string holding a lone
  surrogate (`\ud800`). I report `wrong_type`.
- **Still open:** line 128, "no BOM", is about values. A document that starts
  with a byte-order mark is `invalid_json` in this verifier.

### 2.6 Number notation in record fields (still open, now sharper)

The anchor's `entry_count` may be written in "any notation" (lines 898-900).
Nothing says the same of a record's integer fields. Line 90 says "no float
anywhere in the evidentiary path", and lines 124-125 make "`-0`, a leading `+`,
leading zeros, and any payload that is not valid decimal ASCII" a failure.

I keep record integers to JSON integer literals. `13.0`, `1.3e1` and `-0` in a
record field are `wrong_type`. There is no range check: line 221's `i64` covers
only scores, and line 148 bounds only the length.

For the anchor, I read `-0` and `-0.0` as the count 0, since "whose value is a
non-negative integer" (lines 898-899) is about value, not spelling. A count written with an
exponent too large to represent stays readable and exceeds every record count.
A count whose value is not an integer, such as `1e-999999999999999999999` or
`2.5`, is `anchor_unreadable`.

### 2.7 What runs after a rule 1 failure (partly resolved)

- **Resolved:** "The chain checks are made whatever rules 1 to 4 find, and each
  finding is reported with its code" (lines 1025-1026). Every violation in a
  record is reported, and the chain checks always run.
- **Still open:** whether rule 3 runs on a record that failed rule 1. I skip
  it: a field that does not decode has no preimage.
- **Still open:** rule 1's member check needs the kind's table, but
  `unknown_kind` is rule 2 (lines 948-949). For an `event_kind` with no schema I
  check only the envelope members and `hash`.
- **Still open:** the per-preimage bound (lines 951-952) is measured only on a
  record whose fields all decode.
- **Still open:** a wrong-length `features_canonical` is `feature_arity` (rule
  2, lines 950-951), even though the type column reads "array of integer,
  exactly 27" (line 333).

### 2.8 Smaller wording conflicts with no behaviour choice left (still open)

- Lines 198-200 say arity drift "surfaces as a hash mismatch". Under rule 1 a
  missing or extra member fails `missing_field` or `unknown_member` first.
  Field 2 always comes from the section 2.2 table (line 202).
- The envelope table lists fields 1 and 2 (lines 275-276), and line 927 makes
  "any envelope field" that is missing a `missing_field`. Neither has a member
  name, so the member check covers `seq`, `prev_hash`, `event_kind`, `id`,
  `timestamp_us` and `hash`.

### 2.9 "Index", and records outside the walk (still open, extended)

The spec reports failures "at that index" (lines 129 and 918-919) and words
breaks as "break at or before index N" (lines 1044-1045), but never defines the
word. Mine is the position in the walk.

A record with "no place in the walk" (lines 1028-1029) has no such position. Its
rule 1 findings carry `index: null` and `position`, its place in the `records`
array, and the report shows `records[N], not in the walk`. `duplicate_seq` is
reported at each record after the first at a repeated `seq`.

### 2.10 The anchor position when some records lack an integer seq (new)

The record count is "the number of elements of `records`" (line 889), but the
head check uses "position `entry_count - 1` of the walk" (lines 1002-1004), and
the walk leaves out records with no integer `seq`. When that position is past
the end of the walk, I do not make the head check and add a note; the document
is already `broken` by rule 1. The unanchored-tail count uses the record count,
as lines 1008-1009 say.

### 2.11 Reporting what has no code (new)

Lines 1013-1014 say the verifier "MUST report that truncation of the chain's
tail cannot be detected", and lines 1007-1009 say it "MUST report an unanchored
tail of N records". Neither has a code. I report the first as a note and the
second as `unanchored_tail` and an `unanchored tail` line. Neither is a code, so
neither counts against a document's `expected_codes`.

### 2.12 A `chain_upgrade` after `seq` 0 (still open)

The spec does not say whether one may appear later. I treat it as an ordinary
record under rule 4.

### 2.13 The `$repeat` directive (still open)

- Lines 46-48 call the problem "the vectors-file `$repeat` directive with
  anything written beside it", but lines 430-436 make any directive in a
  document a wrong type. A bare, well-formed directive in a document is
  `wrong_type` here.
- The loader expands it only where it is a field's value (lines 410-411), before
  decoding (lines 424-425), with its shape checked strictly (lines 417-420).

### 2.14 Gate decisions (still open)

Lines 962-968 say an unrecognised pair must not be counted or presented as an
allow, and should be reported raw. Allows are counted only by the four pairs of
lines 555-557.

*Failed verification* is my own line. A record is excluded from the count if:

- it has any finding at its walk index;
- it sits in the `seq` group just before a `link_break`, because a record
  "altered and re-hashed reports at the following index" (lines 1042-1043);
- or it is outside the walk.

An unrecognised pair is listed only when both values are strings. A NULL
`response_hash_delivered` is never called missing data (line 509).

### 2.15 Checks deliberately not made (still open)

Line 50 says "section 7 rule 1 lists every check a record makes to decode",
and lines 954-960 say a token outside a vocabulary is not a failure. Not
checked:

- Producer semantics. For example `held_ms` 0 on (`hold`, `allow`) (line 563),
  and the hashes on `shutdown_deny`, which "are both present, and they differ"
  (line 656).
- Content against its digests and lengths (sections 4.2 and 4.3).
- The section 3 slot rules for `features_canonical`.
- Cross-record identity.
- Time gaps around `protection_on`/`protection_off` (lines 698-701).
- Closed vocabularies. Line 612 ("the token table below wins over any
  attribute") and lines 688-689 ("`event` is one of") read as closed sets, but
  lines 954-960 decide.

### 2.16 Escaping and resource bounds (my choices, unchanged)

Lines 970-971 require escaping every document string shown to a person. Every
value is shown as ASCII JSON. A string is cut at 160 characters before it is
escaped, an integer at 40 digits, and a nested value at depth 2 and width 4.

`--json` writes `seq` values as strings, because an integer field needs no
double-precision rounding. Only the first 1000 findings keep their details, and
all are counted. One million `{}` records (3 MB) peaked at about 260 MB.

### 2.17 Spec contradictions that change no verifier behaviour

Still open:

- Lines 388-389 set `_truncated` "whenever the full content exceeded the cap",
  but lines 444-446 store a non-UTF-8 body with "`_truncated` false".
- Lines 1398-1399 put `app_version` on "a `lifecycle` `shutdown` record", but
  lines 684-686 make it a non-nullable field of every `lifecycle` record.
- Lines 815-816 read "This is the fourth badge state for Track B", and which row
  "this" means is still unclear. The section 6 table no longer applies to a
  document (lines 798-800), so this no longer matters to a verifier.

Resolved:

- **Resolved** by lines 26-29: the previous revision limited the document to
  the bytes hashed, against section 7's document rules. The scope now includes
  "the four top-level members of a 2.x document a verifier reads and the checks
  it makes".
- **Resolved** by lines 707-711: the anchor on shutdown "covers the `shutdown`
  record and every record before it. That is not always the chain head", which
  matches section 4.7.1 (lines 657-660).
- **Resolved** by lines 1279-1284: section 9 now says the keychain anchor "is
  the only truncation detection that does not rest on the document", which no
  longer conflicts with section 7's document checks.
- **Resolved** by lines 1124-1127: 7.1 now names both forms of the 1.x/2.x
  mismatch.

## 3. Vectors I disagree with

None of these affects a hash, a verdict or a code. Every vector reproduces.

1. **Resolved.** `neg_duplicate_member` and `neg_duplicate_member_mirror` now
   list `acceptable_violations` `["duplicate_member", "hash_mismatch"]`, and
   their `expected_outcome` gives the other copy's recompute, `0f11ea11...`,
   which I had reported.
2. **Resolved.** `neg_relabelled_1_0.expected_outcome` now says "No 1.0 walk
   detects the edit to record 2", and that the README walk "fails the same
   document with record 2 unedited in the same place". The runner checks both
   claims. Its `basis` now names one vector (`interaction_full_nonascii`),
   which can be looked up, although the document is built from three records.
3. **Still open.** The `interaction_second_conversation` note says "Identical
   to interaction_full_nonascii except conversation_ref", but `id` differs too:
   `01JQ00000000000000000000FD` against `01JQ0000000000000000000002`.
4. **Resolved.** The `gate_decision_client_disconnected` note now reads "A hold
   during which the producer found that the client had gone (section 4.4)", the
   corrected wording of the erratum (lines 1146-1154).
5. **Still open.** Five interaction vectors carry `execution_gate_id`
   `"gate-9"`, while lines 374-376 say the field is "always NULL until Track A
   writes it". Legal, but no note marks the value hypothetical.
6. **Still open.** `held_ms` 14320, 2150, 6100 and 9400 are not whole seconds
   times 1000, which appendix B line 1452 says Vigil 2.3.2 writes. That line is
   non-normative, and no note says the values are hypothetical.
7. **Still open.** `chain_truncation` at `seq` 10 records
   `observed_entry_count` 12 and `observed_head_hash` `ffff...`. These are
   inconsistent with its own position: ten records precede it, and the stored
   hash at `seq` 9 is `eeced3a5...`.
8. **Still open, and now in conflict with the spec.** The `lifecycle_shutdown`
   note still says "the anchor and the chain head are the same event and a
   clean quit can never leave the anchor lagging". Revised section 4.7b says the
   anchor covers the `shutdown` record and "That is not always the chain head"
   (lines 708-711).
9. **Still open.** Informative restatements:
   - `limits` omits the 2^24 preimage limit (line 150).
   - `feature_slots.order` uses relative ranges where section 3 uses absolute
     slots (line 247).
   - `repeat_directive.rule` (vectors-file line 15) still says "before hashing"
     where line 425 says "before the record is decoded".
10. **Resolved.** The coverage claim at lines 1193-1195 now has its cases.
    `neg_field_over_limit`, `neg_held_ms_string` and `neg_id_null` name
    `over_limit`, `wrong_type` and `null_field` (line 1199). The "Used here"
    list (line 1244) no longer names `link_break` and now names `over_limit`.

## 4. Coverage the vectors do not give

The 13 negative documents now cover:

- a middle deletion, a re-linked gap, and record 0 not a `chain_upgrade`;
- an over-long anchor, a head mismatch, and a duplicate `seq`;
- a duplicate `records`, a missing `voaf_version`, and a missing or null
  genesis;
- an empty store, and an absent or unreadable anchor.

These remain without a vector, and each is exercised by the derived block of
`run_vectors.py` instead:

- **Chain checks:** `root_missing` (including a negative lowest `seq`),
  `root_genesis_mismatch`, more than one record at `seq` 0, an anchor head that
  matches with a tail, `anchor_head_mismatch` while `entry_count` is below the
  record count, and an `entry_count` in other notations (`13.0`, `1.1e1`,
  `1e400`).
- **Anchors:** `anchor_null` on a document that has records, a head-less
  anchor, and zero records with an anchor above 0.
- **Document checks:** `invalid_json`, `malformed_member`, version strings such
  as `01.0`, `02`, `2.` and `voaf-2.0`, an empty top-level array, and genuine
  1.0 documents in both shapes.
- **Rule 2:** `unknown_kind`, `feature_arity`, and the 2^24 preimage bound
  (inclusive).
- **Records:** records with no integer `seq`, or not objects, which fall
  outside the walk; and wrong scalar types other than a string `held_ms`.
- **Gate pairs:** (`hold`, `allow`), an unrecognised pair, and records that fail
  rule 4 or are re-hashed.
- **Values that must verify:** a restore with a NULL upstream digest, a
  truncated `ai_response`, negative scalars, uppercase and 63-character digests,
  content 3 bytes under the cap, and strings that need escapes.
- **Robustness:** escaping, the command line and its exit codes, very long
  integers, and many failing records.

The vectors' content digests remain consistent. `user_message_sha256` and
`ai_response_sha256` match their content, and the truncated vectors' digests
match `'A' * 1048586` and `'日' * 400000`. `neg_field_over_limit`'s digest and
length describe its 1,048,577-byte content.
