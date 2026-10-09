#!/usr/bin/env python3
"""Verify a VOAF 2.x document.

Implements spec/2.0/preimage.md (revision 4, spec release 2.1.0, format tag
voaf-2.0) from the spec text and its vectors file alone, with the Python 3
standard library only.

    python3 voaf_verify.py DOCUMENT [--genesis HEX | --install-nonce HEX] [--json]

DOCUMENT is a path, or "-" for standard input. The verdicts are section 7's;
the spec defines no exit codes, so these are this implementation's (NOTES.md).
Only `verified` exits 0. Codes 4 and 5 are retired: spec commit 08f06db says the
section 6 table, whose `unanchored` and `lost` they carried, does not apply to a
document.

    0  verified            6  rejected           10  usage or input error, --help
    1  broken              7  1.0-linkage-only   11  internal error
    2  truncated           8  1.0-link-broken
    3  empty               9  1.0-empty
"""

import argparse
import hashlib
import json
import os
import re
import sys

TAG = "voaf-2.0"
MAX_FIELD_BYTES = 1 << 20          # section 2.1; every limit is inclusive
MAX_ARRAY_ELEMENTS = 1 << 16
MAX_PREIMAGE_BYTES = 1 << 24
FEATURE_SLOTS = 27                 # section 3 and section 7 rule 2
GENESIS_PREFIX = b"vigil-genesis"  # section 5
ZERO_HASH = "0" * 64               # entry 0 anchor of the 1.0 walk (NOTES.md)
MAX_STORED_FINDINGS = 1000         # findings kept with details; all are counted
MAX_LISTED_PAIRS = 100             # unrecognised gate pairs listed; all are counted

EXIT = {"verified": 0, "broken": 1, "truncated": 2, "empty": 3, "rejected": 6,
        "1.0-linkage-only": 7, "1.0-link-broken": 8, "1.0-empty": 9}
EXIT_USAGE = 10
EXIT_INTERNAL = 11

STR, INT, BOOL = "string", "integer", "bool"
ARR_STR, ARR_INT = ("array", STR), ("array", INT)
MARKER = {STR: 1, INT: 2, BOOL: 3}

# Section 4: (member, type, nullable) in preimage order. Fields 1 and 2, the
# tag and the field count, are not members of a record.
ENVELOPE = (("seq", INT, False), ("prev_hash", STR, False), ("event_kind", STR, False),
            ("id", STR, False), ("timestamp_us", INT, False))
KINDS = {
    "interaction": (                                                    # 4.1
        ("provider", STR, False), ("model", STR, True),
        ("interaction_type", STR, False), ("conversation_ref", STR, True),
        ("client_ref", STR, True), ("user_message", STR, True),
        ("user_message_sha256", STR, True), ("user_message_length", INT, True),
        ("user_message_truncated", BOOL, False), ("ai_response", STR, True),
        ("ai_response_sha256", STR, True), ("ai_response_length", INT, True),
        ("ai_response_truncated", BOOL, False), ("action", STR, False),
        ("scope", STR, False), ("features_canonical", ARR_INT, False),
        ("risk_tier", STR, False), ("anomaly_score_canonical", INT, True),
        ("is_anomaly", BOOL, False), ("policy_action", STR, False),
        ("matched_policy", STR, True), ("blocked", BOOL, True),
        ("block_reason", STR, True), ("policy_id", STR, True),
        ("gate_layer", INT, True), ("tap_certificate_id", STR, True),
        ("scope_violation", BOOL, False), ("execution_gate_id", STR, True)),
    "gate_decision": (                                                  # 4.4
        ("gate_id", STR, False), ("interaction_id", STR, True),
        ("provider", STR, False), ("protocol", STR, False),
        ("tool_call_id", STR, True), ("tool_name", STR, True),
        ("class", STR, False), ("rule_ids", ARR_STR, False),
        ("verdict", STR, False), ("decision", STR, False),
        ("held_ms", INT, False), ("snapshot_ids", ARR_STR, False),
        ("response_hash_upstream", STR, True), ("response_hash_delivered", STR, True),
        ("actor", STR, False), ("policy_version", STR, False)),
    "chain_upgrade": (                                                  # 4.5
        ("predecessor_format_version", STR, True),
        ("predecessor_document_sha256", STR, True),
        ("predecessor_record_count", INT, True), ("predecessor_head_hash", STR, True)),
    "chain_truncation": (                                               # 4.6
        ("anchor_entry_count", INT, False), ("anchor_head_hash", STR, False),
        ("observed_entry_count", INT, False), ("observed_head_hash", STR, False)),
    "lifecycle": (                                                      # 4.7b
        ("event", STR, False), ("app_version", STR, False), ("reason", STR, True)),
}
# Section 2.2: normative, and never recomputed from the tables above.
FIELD_COUNT = {"interaction": 35, "gate_decision": 23, "chain_upgrade": 11,
               "chain_truncation": 11, "lifecycle": 10}

# Section 4.4.1. An allow is one of the first four pairs, judged by the pair.
ALLOW_PAIRS = frozenset({("allow", "allow"), ("hold", "allow"), ("hold", "user_approve"),
                         ("hold", "always_allow")})
OTHER_PAIRS = frozenset({("hold", "user_deny"), ("hold", "timeout_deny"),
                         ("hold", "client_disconnected"), ("hold", "shutdown_deny"),
                         ("hold", "connection_panicked"), ("allow", "restore")})

# Section 7's code table: the verdict each code carries. `malformed_entry`, a
# 1.0 walk code, is this implementation's (NOTES.md).
REJECTING = frozenset({"invalid_json", "duplicate_member", "unrecognised_format",
                       "format_mismatch", "missing_member", "malformed_member"})
BROKEN = frozenset({"unknown_member", "missing_field", "wrong_type", "null_field",
                    "null_element", "over_limit", "unknown_kind", "feature_arity",
                    "hash_mismatch", "link_break", "duplicate_seq", "anchor_head_mismatch"})
TRUNCATED = frozenset({"root_missing", "root_not_chain_upgrade", "root_genesis_mismatch",
                       "seq_gap", "anchor_exceeds_records"})
INFORMATIONAL = frozenset({"anchor_absent", "anchor_null", "anchor_unreadable"})

_MISSING = object()


# --- JSON text --------------------------------------------------------------

class JInt:
    """A JSON integer kept as the literal the document wrote, so that nothing is
    coerced on the way to the preimage (section 2) and nothing converts a huge
    literal to a number."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text

    def __eq__(self, other):
        return isinstance(other, JInt) and other.text == self.text

    def __hash__(self):
        return hash(("JInt", self.text))

    def __repr__(self):
        return "JInt(%s)" % self.text


class JNum:
    """A JSON number written with a fraction or exponent, kept as its literal. It is
    never an integer field's value (section 2: no float in the evidentiary path), but
    the anchor's entry_count is read by value in any notation (section 7)."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text

    def __eq__(self, other):
        return isinstance(other, JNum) and other.text == self.text

    def __hash__(self):
        return hash(("JNum", self.text))

    def __repr__(self):
        return "JNum(%s)" % self.text


class Rejected(Exception):
    """A document that is not walked at all."""
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


def _no_repeated_names(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise Rejected("duplicate_member", "an object repeats the member name %s; "
                           "none of the document's records is walked" % esc(name))
        obj[name] = value
    return obj


def _not_json(name):
    raise Rejected("invalid_json", "%s is not a JSON value" % name)


def parse_json(data):
    """Parse one JSON value from bytes or str. A repeated member name in any object,
    at any depth, is rejected while parsing (section 7, RFC 7493 section 2.3)."""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise Rejected("invalid_json", "the document is not UTF-8 text (%s at byte %d)"
                           % (e.reason, e.start))
    try:
        return json.loads(data, object_pairs_hook=_no_repeated_names, parse_int=JInt,
                          parse_float=JNum, parse_constant=_not_json)
    except Rejected:
        raise
    except (ValueError, RecursionError) as e:
        raise Rejected("invalid_json", "the document is not one JSON value (%s)"
                       % str(e).splitlines()[0][:200])


def dump_json(value, ascii_only=False):
    """Serialise a parsed value back to JSON text, writing a JInt as its literal.
    Used for documents built from the vectors file; esc() shows untrusted values."""
    if isinstance(value, (JInt, JNum)):
        return value.text
    if value is None or type(value) in (bool, int, float):
        return json.dumps(value)
    if type(value) is str:
        return json.dumps(value, ensure_ascii=ascii_only)
    if type(value) is list:
        return "[" + ", ".join(dump_json(v, ascii_only) for v in value) + "]"
    if type(value) is dict:
        return "{" + ", ".join(json.dumps(k, ensure_ascii=ascii_only) + ": "
                               + dump_json(v, ascii_only) for k, v in value.items()) + "}"
    raise TypeError("cannot serialise %r" % type(value))


def _brief(value, limit, depth=0):
    """ASCII JSON for a value of any shape. A string is cut to `limit` characters
    before it is escaped, so a cut never splits an escape; an integer is cut by its
    digits; a nested value is shown to depth 2 and width 4 with short strings, so a
    deep or huge document value cannot exhaust the stack or the output."""
    if isinstance(value, JInt):
        return show_int(value.text)
    if isinstance(value, JNum):
        return value.text if len(value.text) <= 40 else "%s...(%d characters)" % (
            value.text[:20], len(value.text))
    if type(value) is str:
        if len(value) <= limit:
            return json.dumps(value, ensure_ascii=True)
        return "%s...(%d characters in all)" % (json.dumps(value[:limit], ensure_ascii=True),
                                               len(value))
    if type(value) not in (list, dict):
        return json.dumps(value)
    if depth >= 2:
        return "[...]" if type(value) is list else "{...}"
    if type(value) is dict:
        parts = ["%s: %s" % (_brief(k, 40, depth + 1), _brief(v, 40, depth + 1))
                 for k, v in list(value.items())[:4]]
    else:
        parts = [_brief(e, 40, depth + 1) for e in value[:4]]
    if len(value) > 4:
        parts.append("...(%d in all)" % len(value))
    return ("{%s}" if type(value) is dict else "[%s]") % ", ".join(parts)


def esc(value, limit=160):
    """Show a document-supplied value to a person: JSON-escaped and ASCII only, so a
    document cannot forge or hide this verifier's output (section 7 rule 2). A string
    over `limit` characters is cut and its full length shown."""
    return _brief(value, limit)


def jtype(v):
    """What a JSON value is, for messages."""
    if v is None:
        return "null"
    if type(v) is bool:
        return "a boolean"
    if isinstance(v, JInt):
        return "the integer -0, which is not canonical decimal" if v.text == "-0" else "an integer"
    if type(v) is int:
        return "an integer"
    if isinstance(v, JNum) or type(v) is float:
        return "a number that is not an integer literal"
    if type(v) is str:
        return "a string"
    if type(v) is list:
        return "an array"
    if type(v) is dict:
        return "an object"
    return type(v).__name__


# --- Integers kept as text ------------------------------------------------------

_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_INVERT = str.maketrans("0123456789", "9876543210")


def int_text(v):
    """Canonical decimal ASCII of an integer value, or None: no -0, no leading + or
    zeros, nothing but ASCII digits (section 2)."""
    if isinstance(v, JInt):
        text = v.text
    elif type(v) is int:
        text = str(v)
    else:
        return None
    return text if text != "-0" and _DECIMAL.match(text) else None


def int_key(text):
    """Sort key for canonical decimal text, in numeric order, with no conversion."""
    if text.startswith("-"):
        return (0, -len(text), text[1:].translate(_INVERT))
    return (1, len(text), text)


def int_succ(text):
    """text + 1, as canonical decimal text."""
    if text.startswith("-"):
        m = text[1:]
        i = len(m) - 1
        while m[i] == "0":
            i -= 1
        less = (m[:i] + chr(ord(m[i]) - 1) + "9" * (len(m) - i - 1)).lstrip("0") or "0"
        return "0" if less == "0" else "-" + less
    i = len(text) - 1
    while i >= 0 and text[i] == "9":
        i -= 1
    if i < 0:
        return "1" + "0" * len(text)
    return text[:i] + chr(ord(text[i]) + 1) + "0" * (len(text) - i - 1)


def show_int(text):
    """An integer for output: whole up to 40 digits, else cut with its digit count."""
    if text is None:
        return "?"
    digits = len(text) - text.startswith("-")
    return text if digits <= 40 else "%s...(%d digits)" % (text[:20], digits)


# --- Section 2: the preimage -------------------------------------------------

def _header(marker, n):
    return bytes((marker,)) + n.to_bytes(4, "big")


def encode_value(ftype, v):
    """Section 2 encoding of one field value. It does not validate: check_record calls
    it only on values that decoded, and run_vectors.py uses it to model readers that
    lack a check."""
    if v is None:
        return b"\x00"
    if isinstance(ftype, tuple):
        return _header(4, len(v)) + b"".join(encode_value(ftype[1], e) for e in v)
    if ftype == STR:
        payload = v.encode("utf-8")
    elif ftype == INT:
        payload = int_text(v).encode("ascii")
    else:
        payload = b"1" if v else b"0"
    return _header(MARKER[ftype], len(payload)) + payload


def genesis_from_nonce(nonce):
    """Section 5: SHA256(b"vigil-genesis" || install_nonce_raw_32), lowercase hex."""
    if len(nonce) != 32:
        raise ValueError("an install nonce is 32 raw bytes")
    return hashlib.sha256(GENESIS_PREFIX + nonce).hexdigest()


class PreimageError(Exception):
    def __init__(self, code, offset, detail):
        super().__init__("%s at byte %d: %s" % (code, offset, detail))
        self.code, self.offset, self.detail = code, offset, detail


def decode_preimage(data):
    """Read preimage bytes back into fields, each None or (type, value), an array as
    ("array", [elements]). Every u32be header is checked against section 2.1 before
    the payload it declares is read, and every payload against section 2."""
    if len(data) > MAX_PREIMAGE_BYTES:
        raise PreimageError("over_limit", 0, "%d bytes, above the 2^24 limit" % len(data))
    fields, pos = [], 0
    while pos < len(data):
        value, pos = _read_field(data, pos, None)
        fields.append(value)
    return fields


def _read_field(data, pos, element_marker):
    start, marker = pos, data[pos]
    if marker == 0:
        if element_marker is not None:
            raise PreimageError("null_element", start, "an array element is NULL")
        return None, pos + 1
    if marker not in (1, 2, 3, 4):
        raise PreimageError("malformed", start, "unknown marker 0x%02x" % marker)
    if element_marker is not None and marker != element_marker:
        raise PreimageError("wrong_type", start, "array elements are not homogeneous")
    if pos + 5 > len(data):
        raise PreimageError("malformed", start, "the u32be header is cut short")
    n = int.from_bytes(data[pos + 1:pos + 5], "big")
    pos += 5
    if marker == 4:
        if n > MAX_ARRAY_ELEMENTS:
            raise PreimageError("over_limit", start, "array count %d, above the 2^16 limit" % n)
        items, first = [], None
        for _ in range(n):
            if pos >= len(data):
                raise PreimageError("malformed", pos, "the array is cut short")
            if first is None:
                first = data[pos]
                if first == 0:
                    raise PreimageError("null_element", pos, "an array element is NULL")
                if first == 4:
                    raise PreimageError("wrong_type", pos, "nested arrays are not legal")
            item, pos = _read_field(data, pos, first)
            items.append(item)
        return ("array", items), pos
    if n > MAX_FIELD_BYTES:
        raise PreimageError("over_limit", start, "u32be length %d, above the 2^20 limit" % n)
    if pos + n > len(data):
        raise PreimageError("malformed", start, "the payload is cut short")
    payload, pos = data[pos:pos + n], pos + n
    if marker == 1:
        try:
            return (STR, payload.decode("utf-8")), pos
        except UnicodeDecodeError:
            raise PreimageError("wrong_type", start, "a string payload is not valid UTF-8")
    if marker == 2:
        text = payload.decode("ascii", "replace")
        if not payload.isascii() or int_text(JInt(text)) is None:
            raise PreimageError("wrong_type", start, "an integer payload is not canonical decimal ASCII")
        return (INT, text), pos
    if payload not in (b"0", b"1"):
        raise PreimageError("wrong_type", start, "a bool payload is not exactly 0x30 or 0x31")
    return (BOOL, payload == b"1"), pos


# --- Section 7 rules 1 to 3: one record ----------------------------------------

class RecordResult:
    """What section 7 rules 1 to 3 conclude about one record."""
    __slots__ = ("problems", "kind", "seq", "prev_hash", "stored", "preimage", "computed")

    def __init__(self):
        self.problems = []      # (code, detail) in the order found
        self.kind = None        # event_kind, when it names a schema
        self.seq = None         # seq as canonical decimal text, when it decodes
        self.prev_hash = None   # prev_hash, when it is a string
        self.stored = None      # the hash member, when it is a string
        self.preimage = None    # set only when every field decodes
        self.computed = None    # SHA256(preimage), lowercase hex


def _scalar_problem(ftype, v):
    if ftype == STR:
        if type(v) is not str:
            return "wrong_type", "expected a string, found %s" % jtype(v)
        try:
            size = len(v.encode("utf-8"))
        except UnicodeEncodeError:
            return "wrong_type", "the string holds a lone surrogate, so it has no UTF-8 encoding"
    elif ftype == INT:
        text = int_text(v)
        if text is None:
            return "wrong_type", "expected an integer, found %s" % jtype(v)
        size = len(text)
    else:
        if type(v) is not bool:
            return "wrong_type", "expected a boolean, found %s" % jtype(v)
        size = 1
    if size > MAX_FIELD_BYTES:
        return "over_limit", "its u32be length header would be %d, above the 2^20 limit" % size
    return None


def _field_problems(name, ftype, nullable, v):
    if v is None:
        return [] if nullable else [("null_field", "%s is NULL, and section 4 marks it not "
                                                   "nullable" % name)]
    if not isinstance(ftype, tuple):
        p = _scalar_problem(ftype, v)
        return [(p[0], "%s: %s" % (name, p[1]))] if p else []
    if type(v) is not list:
        return [("wrong_type", "%s: expected an array, found %s" % (name, jtype(v)))]
    out = []
    if len(v) > MAX_ARRAY_ELEMENTS:
        out.append(("over_limit", "%s: its u32be count header would be %d, above the 2^16 "
                                  "limit" % (name, len(v))))
    for i, e in enumerate(v):
        if e is None:
            out.append(("null_element", "%s[%d] is NULL; array elements are never NULL"
                        % (name, i)))
        else:
            p = _scalar_problem(ftype[1], e)
            if p:
                out.append((p[0], "%s[%d]: %s" % (name, i, p[1])))
    return out


def check_record(rec, require_hash=True, tag=TAG, field_count=None, keep_preimage=True):
    """Apply section 7 rules 1 to 3 to one parsed record. `tag` and `field_count`
    exist only so run_vectors.py can reproduce the mutation vectors; a verifier never
    varies them. `require_hash` is false only for vectors[].record, which carries none."""
    res = RecordResult()
    if type(rec) is not dict:
        res.problems.append(("wrong_type", "the record is %s, not an object" % jtype(rec)))
        return res
    kind = rec.get("event_kind", _MISSING)
    if kind is _MISSING:
        res.problems.append(("missing_field", "event_kind is missing"))
    elif kind is None:
        res.problems.append(("null_field", "event_kind is NULL, and the envelope marks it "
                                           "not nullable"))
    elif type(kind) is not str:
        res.problems.append(("wrong_type", "event_kind: expected a string, found %s"
                             % jtype(kind)))
    elif kind not in KINDS:
        res.problems.append(("unknown_kind", "event_kind %s has no schema in this document"
                             % esc(kind)))
    else:
        res.kind = kind
    table = ENVELOPE + KINDS.get(res.kind, ())
    if res.kind:  # with no schema, only the envelope can be checked
        declared = {name for name, _, _ in table}
        for name in rec:
            if name != "hash" and name not in declared:
                res.problems.append(("unknown_member", "%s is not a member of a %s record"
                                     % (esc(name), res.kind)))
    for name, ftype, nullable in table:
        if name == "event_kind":
            continue
        if name not in rec:
            res.problems.append(("missing_field", "%s is missing (an absent field is not "
                                                  "a NULL)" % name))
        else:
            res.problems.extend(_field_problems(name, ftype, nullable, rec[name]))
    stored = rec.get("hash", _MISSING)
    if stored is _MISSING:
        if require_hash:
            res.problems.append(("missing_field", "hash is missing"))
    elif stored is None:
        res.problems.append(("null_field", "hash is NULL; the stored hash is a string"))
    elif type(stored) is not str:
        res.problems.append(("wrong_type", "hash: expected a string, found %s" % jtype(stored)))
    else:
        res.stored = stored
    res.seq = int_text(rec.get("seq"))
    if type(rec.get("prev_hash")) is str:
        res.prev_hash = rec["prev_hash"]
    if res.kind == "interaction":                                     # rule 2
        features = rec.get("features_canonical")
        if type(features) is list and len(features) != FEATURE_SLOTS:
            res.problems.append(("feature_arity", "features_canonical holds %d elements, "
                                                  "not exactly 27" % len(features)))
    if res.problems:
        return res
    count = FIELD_COUNT[res.kind] if field_count is None else field_count
    preimage = b"".join([encode_value(STR, tag), encode_value(INT, count)]
                        + [encode_value(ftype, rec[name]) for name, ftype, _ in table])
    if len(preimage) > MAX_PREIMAGE_BYTES:                            # rule 2
        res.problems.append(("over_limit", "the preimage is %d bytes, above the 2^24 limit"
                             % len(preimage)))
        return res
    res.computed = hashlib.sha256(preimage).hexdigest()
    if keep_preimage:
        res.preimage = preimage
    if res.stored is not None and res.computed != res.stored:          # rule 3
        res.problems.append(("hash_mismatch", "recomputed %s, stored %s"
                             % (res.computed, esc(res.stored))))
    return res


# --- Section 7: the document ----------------------------------------------------

class Report:
    def __init__(self):
        self.verdict = None
        self.format = None          # "2.x", "1.0", or None when not walked
        self.declared = None        # voaf_version as the document wrote it
        self.records = 0            # the record count: elements of `records`
        self.walked = 0             # records with an integer seq, the walk
        self.findings = []          # {"index", "position", "seq", "code", "detail"}
        self.codes = set()          # every finding code, stored or not
        self.counts = {}            # finding code -> number of findings
        self.omitted = 0            # findings counted but not stored
        self.notes = []
        self.genesis = None
        self.anchor = None
        self.head = None
        self.unanchored_tail = 0
        self.gate = None

    @property
    def exit_code(self):
        return EXIT[self.verdict]

    def room(self):
        return len(self.findings) < MAX_STORED_FINDINGS

    def add(self, index, seq, code, detail, position=None):
        self.codes.add(code)
        self.counts[code] = self.counts.get(code, 0) + 1
        if self.room():
            self.findings.append({"index": index, "position": position,
                                  "seq": _json_seq(seq), "code": code, "detail": detail})
        else:
            self.omitted += 1


def _json_seq(text):
    """A seq for output: always its decimal text (cut when long), never a JSON number,
    so its type does not depend on its size and no reader rounds it."""
    return None if text is None else show_int(text)


_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")


def declared_major(v):
    """Section 7's format check: a declared version is runs of ASCII digits separated
    by single dots; a first run of exactly "1" declares 1.x and exactly "2" 2.x. Any
    other value, "01" and "02" included, declares nothing this verifier recognises."""
    if type(v) is str and _VERSION.match(v):
        return {"1": 1, "2": 2}.get(v.split(".", 1)[0])
    return None


V2_ENTRY_MEMBERS = ("event_kind", "seq", "timestamp_us")


def settle_format(doc):
    """Section 7's format check. Returns 2 for a 2.x document or (1, entries) for a
    1.0 one; raises Rejected for a document that is not walked at all."""
    if type(doc) is list:  # "a 1.0 array of entries", each declaring 1.x
        if any(type(e) is not dict or declared_major(e.get("voaf")) != 1 for e in doc):
            raise Rejected("unrecognised_format", "a top-level array is read only as a 1.0 "
                           "array of entries, each declaring a 1.x `voaf`")
        entries = doc
    elif type(doc) is dict:
        declared = doc.get("voaf_version", _MISSING)
        major = declared_major(declared)
        if major == 2:
            return 2
        if major != 1:
            shown = "is missing" if declared is _MISSING else "is %s" % esc(declared)
            raise Rejected("unrecognised_format", "voaf_version %s, which declares neither "
                           "1.x nor 2.x" % shown)
        if "records" in doc:
            raise Rejected("format_mismatch", "the document declares 1.x and carries "
                           "`records`, which only 2.x defines; it is not walked link-only")
        entries = doc.get("interactions", _MISSING)
        if type(entries) is not list:
            raise Rejected("unrecognised_format", "the document declares 1.x but carries no "
                           "`interactions` array")
    else:
        raise Rejected("unrecognised_format", "the document is %s, neither an object nor an "
                       "array of 1.x entries" % jtype(doc))
    for i, e in enumerate(entries):
        found = [m for m in V2_ENTRY_MEMBERS if type(e) is dict and m in e]
        if found:
            raise Rejected("format_mismatch", "the document declares 1.x and entry %d carries "
                           "%s, which only 2.x defines; it is not walked link-only"
                           % (i, ", ".join(found)))
    return 1, entries


def check_members(doc):
    """Section 7's document member check on a 2.x document: `records` an array, and,
    with a record count of 1 or more, `genesis` a string. `null` counts as absent."""
    records = doc.get("records")
    if records is None:
        raise Rejected("missing_member", "the 2.x document carries no `records`")
    if type(records) is not list:
        raise Rejected("malformed_member", "`records` is %s, not an array" % jtype(records))
    if records:
        genesis = doc.get("genesis")
        if genesis is None:
            raise Rejected("missing_member", "the document holds %d records and carries no "
                           "`genesis`" % len(records))
        if type(genesis) is not str:
            raise Rejected("malformed_member", "`genesis` is %s, not a string"
                           % jtype(genesis))
    return records


def verify_bytes(data, genesis=None, genesis_source=None):
    """Verify a document given as JSON text (bytes or str). A supplied genesis is
    compared with the document's and reported, but the verdict follows the document's
    own `genesis` (section 7)."""
    try:
        doc = parse_json(data)
    except Rejected as e:
        return _rejected(Report(), e)
    return verify_document(doc, genesis, genesis_source)


def verify_document(doc, genesis=None, genesis_source=None):
    """Verify a document parsed with parse_json (which made the parse check)."""
    rep = Report()
    try:
        fmt = settle_format(doc)
        rep.declared = doc.get("voaf_version") if type(doc) is dict else None
        if fmt != 2:
            return _walk_v1(fmt[1], rep)
        records = check_members(doc)
    except Rejected as e:
        return _rejected(rep, e)
    return _walk_v2(doc, records, genesis, genesis_source, rep)


def _rejected(rep, e):
    rep.verdict = "rejected"
    rep.format = None
    rep.add(None, None, e.code, e.detail)
    return rep


def v1_link_walk(entries, anchor=ZERO_HASH):
    """The 1.0 link-only walk: each entry's prev_hash equals the stored hash of the
    entry before it, and entry 0's equals `anchor` (unchecked when anchor is None).
    Content is not checked. Yields (entry index, code, detail)."""
    before = anchor
    for k, e in enumerate(entries):
        ph = e.get("prev_hash") if type(e) is dict else None
        h = e.get("hash") if type(e) is dict else None
        if type(ph) is not str or type(h) is not str:
            yield k, "malformed_entry", "entry %d lacks a string prev_hash or hash" % k
        if before is not None and type(ph) is str and ph != before:
            yield (k, "link_break", "break at or before entry %d: prev_hash %s does not equal %s"
                   % (k, esc(ph), esc(before)))
        before = h if type(h) is str else None


def _walk_v1(entries, rep):
    rep.format, rep.records = "1.0", len(entries)
    rep.notes.append("1.0 document: linkage only. No record content was checked, and a 1.0 "
                     "verdict never asserts content integrity (section 7).")
    if not entries:
        rep.verdict = "1.0-empty"
        return rep
    for k, code, detail in v1_link_walk(entries):
        rep.add(k, None, code, detail)
    rep.verdict = "1.0-link-broken" if rep.codes else "1.0-linkage-only"
    return rep


_NUMBER = re.compile(r"(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?\Z")
HUGE_COUNT = 10 ** 40  # stands for any count larger than every record count


def anchor_count(v):
    """Section 7: entry_count is read when it is a JSON number whose value is a
    non-negative integer, in any notation (13, 13.0 and 1.3e1 are one count). Returns
    an int (HUGE_COUNT for any value of more than 40 digits), or None if unreadable.
    The literal is read exactly, never through a float."""
    if isinstance(v, (JInt, JNum)):
        text = v.text
    elif type(v) is int:
        text = str(v)
    else:
        return None
    m = _NUMBER.match(text)
    if not m:
        return None
    sign, whole, frac, exp = m.groups()
    mantissa = whole + (frac or "")
    if not mantissa.strip("0"):
        return 0  # zero in any notation, -0 included
    if sign:
        return None
    exp = exp or "0"
    if len(exp.lstrip("+-").lstrip("0")) > 18:
        return None if exp.startswith("-") else HUGE_COUNT
    e = int(exp) - len(frac or "")
    if e >= 0:
        return HUGE_COUNT if len(mantissa.lstrip("0")) + e > 40 else int(mantissa) * 10 ** e
    if len(mantissa) <= -e or mantissa[e:].strip("0"):
        return None  # a fraction remains
    whole_part = mantissa[:e].lstrip("0") or "0"
    return HUGE_COUNT if len(whole_part) > 40 else int(whole_part)


class _Anchor:
    """The carried anchor (section 7): its kind, `entry_count` read by value, and
    `head_hash` when it is a string. Every other member is ignored."""
    def __init__(self, doc):
        self.count = self.head = None
        if "anchor" not in doc:
            self.kind = "absent"
        elif doc["anchor"] is None:
            self.kind = "null"
        else:
            raw = doc["anchor"]
            obj = raw if type(raw) is dict else {}
            self.count = anchor_count(obj.get("entry_count"))
            if type(obj.get("head_hash")) is str:
                self.head = obj["head_hash"]
            self.kind = "unreadable" if self.count is None else "readable"
            self.raw = raw
        if self.kind == "readable":
            self.shown = "entry_count %s, head_hash %s" % (
                "more than 40 digits" if self.count == HUGE_COUNT else self.count,
                esc(self.head) if self.head is not None else "not a string, so not checked")
        elif self.kind == "unreadable":
            self.shown = "present but unreadable: %s" % esc(self.raw)
        else:
            self.shown = self.kind


def _walk_v2(doc, records, supplied, supplied_source, rep):
    rep.format, rep.records = "2.x", len(records)
    n = len(records)
    genesis = doc["genesis"] if n else None  # with zero records, genesis is not read
    rep.genesis = genesis
    if supplied is not None and n and supplied != genesis:
        rep.notes.append("the document's genesis %s is not the genesis from %s (%s); the "
                         "verdict follows the document's own genesis (section 7)"
                         % (esc(genesis), supplied_source, esc(supplied)))
    anchor = _Anchor(doc)
    rep.anchor = anchor.shown

    # Rules 1 to 3 per record. Only codes are kept; details are rebuilt for the
    # findings that are stored, so memory does not grow with the number of failures.
    results, shared = [], {}
    for rec in records:
        r = check_record(rec, keep_preimage=False)
        codes = tuple(code for code, _ in r.problems)
        r.problems = shared.setdefault(codes, codes)  # one tuple per distinct code list
        r.computed = None
        results.append(r)
    # The walk: records with an integer seq, in ascending seq order (section 7). A
    # record with no integer seq has no place in it.
    walk = sorted((i for i in range(n) if results[i].seq is not None),
                  key=lambda i: int_key(results[i].seq))
    rep.walked = len(walk)
    at = {i: k for k, i in enumerate(walk)}
    groups = []  # [(seq, [walk indices])], one per distinct seq, ascending
    for k, i in enumerate(walk):
        if groups and groups[-1][0] == results[i].seq:
            groups[-1][1].append(k)
        else:
            groups.append((results[i].seq, [k]))
    group_of = {k: g for g, (_, ks) in enumerate(groups) for k in ks}
    flagged = set()  # gate_decision walk indices that a finding may implicate

    def flag(k):
        if walk and 0 <= k < len(walk) and results[walk[k]].kind == "gate_decision":
            flagged.add(k)

    def add(k, code, detail):  # k is a walk index, or None for the whole document
        if k is not None:
            flag(k)
            if code == "link_break":  # "break at or before index N": the record before
                for kk in groups[group_of[k] - 1][1]:
                    flag(kk)
        rep.add(k, None if k is None else results[walk[k]].seq, code, detail,
                None if k is None else walk[k])

    for i in walk + [i for i in range(n) if i not in at]:              # rules 1 to 3
        r = results[i]
        if not r.problems:
            continue
        k = at.get(i)
        if k is not None:
            flag(k)
        if not rep.room():
            for code in r.problems:
                rep.add(k, r.seq, code, None, i)
            continue
        for code, detail in check_record(records[i], keep_preimage=False).problems:
            if code == "hash_mismatch" and k is not None:
                detail = "break at or before index %d: %s" % (k, detail)
            rep.add(k, r.seq, code, detail, i)
    for seq, ks in groups:                                             # seq unique
        for k in ks[1:]:
            add(k, "duplicate_seq", "seq %s is carried by %d records" % (show_int(seq), len(ks)))
    for g in range(1, len(groups)):                                    # gapless
        before, seq = groups[g - 1][0], groups[g][0]
        if int_succ(before) != seq:
            add(groups[g][1][0], "seq_gap", "seq goes from %s to %s"
                % (show_int(before), show_int(seq)))
    for g in range(1, len(groups)):                                    # rule 4
        stored = {results[walk[k]].stored for k in groups[g - 1][1]} - {None}
        if not stored:
            continue  # no string hash before it: that failed rule 1, reported there
        for k in groups[g][1]:
            prev_hash = results[walk[k]].prev_hash
            if prev_hash is not None and prev_hash not in stored:
                add(k, "link_break", "break at or before index %d: prev_hash %s is not the "
                    "stored hash of the record at seq %s, the next lower seq"
                    % (k, esc(prev_hash), show_int(groups[g - 1][0])))
    if groups:                                                         # record 0
        if groups[0][0] != "0":
            add(0, "root_missing", "the lowest seq is %s, not 0" % show_int(groups[0][0]))
        else:
            for k in groups[0][1]:
                raw = records[walk[k]]
                kind = raw.get("event_kind")
                if type(kind) is str and kind != "chain_upgrade":
                    add(k, "root_not_chain_upgrade", "the record at seq 0 is %s, not a "
                        "chain_upgrade" % esc(kind))
                prev_hash = results[walk[k]].prev_hash
                if prev_hash is not None and prev_hash != genesis:
                    add(k, "root_genesis_mismatch", "prev_hash %s is not the document's "
                        "genesis %s" % (esc(prev_hash), esc(genesis)))
    if walk:
        rep.head = results[walk[-1]].stored
    _check_anchor(anchor, n, walk, groups, group_of, results, add, rep)
    rep.gate = _gate_summary(walk, records, results, flagged)
    rep.verdict = ("broken" if rep.codes & BROKEN else "truncated" if rep.codes & TRUNCATED
                   else "empty" if n == 0 else "verified")
    return rep


def _check_anchor(anchor, n, walk, groups, group_of, results, add, rep):
    """Section 7's anchor checks against the records."""
    undetectable = "truncation of the chain's tail cannot be detected from this document"
    if anchor.kind != "readable":
        add(None, "anchor_" + anchor.kind, {
            "absent": "the document has no `anchor` member",
            "null": "the document's `anchor` is null",
            "unreadable": "the document's `anchor` is present but holds no entry_count that "
                          "can be read: %s" % esc(anchor.raw) if anchor.kind == "unreadable"
                          else ""}[anchor.kind])
        rep.notes.append(undetectable)
        return
    count = anchor.count
    if count > n:
        add(None, "anchor_exceeds_records", "the anchor's entry_count %s exceeds the %d "
            "records" % ("of more than 40 digits" if count == HUGE_COUNT else count, n))
        return
    if count == 0:
        if n:
            rep.notes.append("the anchor's entry_count is 0, so " + undetectable)
        return
    if anchor.head is None:
        rep.notes.append("the anchor has no string head_hash, so the head check is not made")
        return
    k = count - 1
    if k >= len(walk):
        rep.notes.append("no record with an integer seq sits at position %d of the walk, so "
                         "the head check is not made" % k)
        return
    stored = {results[walk[kk]].stored for kk in groups[group_of[k]][1]} - {None}
    if not stored:
        return  # no string hash there: that failed rule 1, reported there
    if anchor.head in stored:
        rep.unanchored_tail = n - count
    else:
        add(k, "anchor_head_mismatch", "the anchor's head_hash %s is not the stored hash of "
            "the record at position %d of the walk" % (esc(anchor.head), k))


def _gate_summary(walk, records, results, flagged):
    """Section 4.4.1 and section 7 rule 2: count allows by the pair, never counting a
    record with a finding at its index or a link_break after it, and report an
    unrecognised pair of strings with its raw values (escaped when shown to a person).
    Records outside the walk failed rule 1 and are counted as failed."""
    summary = {"allow": 0, "not_allow": 0, "failed_verification": 0,
               "unrecognised_count": 0, "unrecognised": []}
    at = {i: k for k, i in enumerate(walk)}
    for i, (r, raw) in enumerate(zip(results, records)):
        if r.kind != "gate_decision":
            continue
        k = at.get(i)
        pair = (raw.get("verdict"), raw.get("decision"))
        strings = all(type(v) is str for v in pair)
        known = strings and (pair in ALLOW_PAIRS or pair in OTHER_PAIRS)
        failed = bool(r.problems) or k is None or k in flagged
        if failed:
            summary["failed_verification"] += 1
        elif pair in ALLOW_PAIRS:
            summary["allow"] += 1
        elif known:
            summary["not_allow"] += 1
        if strings and not known:
            summary["unrecognised_count"] += 1
            if len(summary["unrecognised"]) < MAX_LISTED_PAIRS:
                summary["unrecognised"].append({"index": k, "position": i,
                                                "seq": _json_seq(r.seq), "verdict": pair[0],
                                                "decision": pair[1],
                                                "failed_verification": failed})
    return summary


# --- Output ----------------------------------------------------------------------

def _where(f):
    if f["index"] is not None:
        return "index %d (seq %s)" % (f["index"], "?" if f["seq"] is None else f["seq"])
    if f["position"] is not None:
        return "records[%d], not in the walk" % f["position"]
    return "document"


def render(rep, source, max_findings=100):
    """The report for a person. Every document-supplied string is escaped."""
    out = ["VOAF verification of %s" % esc(source)]
    if rep.format == "2.x":
        out.append("format          2.x (voaf_version %s); preimage tag %s"
                   % (esc(rep.declared), TAG))
        out.append("genesis         %s, the document's `genesis` member, which no hash covers"
                   % esc(rep.genesis) if rep.genesis is not None
                   else "genesis         not read (zero records)")
        out.append("records         %d, %d walked in ascending seq order"
                   % (rep.records, rep.walked))
        out.append("anchor          %s" % rep.anchor)
        if rep.head is not None:
            out.append("head            %s" % esc(rep.head))
        if rep.unanchored_tail:
            out.append("unanchored tail %d records after the anchored prefix"
                       % rep.unanchored_tail)
        if rep.gate:
            g = rep.gate
            out.append("gate_decision   %d allow, %d not an allow, %d unrecognised pair(s), "
                       "%d failed verification (never counted as an allow)"
                       % (g["allow"], g["not_allow"], g["unrecognised_count"],
                          g["failed_verification"]))
            for u in g["unrecognised"]:
                out.append("  unrecognised pair at %s: verdict %s, decision %s; not counted as "
                           "an allow%s" % (_where(u), esc(u["verdict"]), esc(u["decision"]),
                                           " (the record failed verification)"
                                           if u["failed_verification"] else ""))
            if g["unrecognised_count"] > len(g["unrecognised"]):
                out.append("  ... %d more unrecognised pairs"
                           % (g["unrecognised_count"] - len(g["unrecognised"])))
    elif rep.format == "1.0":
        out.append("format          1.0 document%s, %d entries, link-only"
                   % (" (voaf_version %s)" % esc(rep.declared) if rep.declared is not None
                      else "", rep.records))
    else:
        out.append("format          not walked")
    total = len(rep.findings) + rep.omitted
    out.append("findings        %d" % total)
    for f in rep.findings[:max_findings]:
        tag = " (informational)" if f["code"] in INFORMATIONAL else ""
        out.append("  %s  %s%s: %s" % (_where(f), f["code"], tag,
                                       f["detail"] or "(details not kept)"))
    if total > max_findings:
        out.append("  ... %d more (by code: %s)" % (total - max_findings, ", ".join(
            "%s %d" % (c, k) for c, k in sorted(rep.counts.items()))))
    for note in rep.notes:
        out.append("note: %s" % note)
    out.append("verdict         %s (exit %d)" % (rep.verdict, rep.exit_code))
    return "\n".join(out)


def report_json(rep):
    return json.dumps({
        "verdict": rep.verdict, "exit_code": rep.exit_code, "format": rep.format,
        "declared_version": rep.declared if type(rep.declared) is str else None,
        "records": rep.records, "walked": rep.walked, "genesis": rep.genesis,
        "anchor": rep.anchor, "head": rep.head, "unanchored_tail": rep.unanchored_tail,
        "codes": sorted(rep.codes), "gate_decisions": rep.gate, "findings": rep.findings,
        "findings_omitted": rep.omitted, "finding_counts": rep.counts, "notes": rep.notes,
    }, ensure_ascii=True, indent=1)


def _say(text):
    """Write to stderr if there is one; a closed or broken stderr must not change the
    exit code."""
    try:
        sys.stderr.write(text)
        sys.stderr.flush()
    except Exception:
        pass


class _ArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        try:
            super()._print_message(message, file)
        except Exception:
            pass

    def error(self, message):
        self.print_usage(sys.stderr)
        _say("error: %s\n" % message)
        sys.exit(EXIT_USAGE)

    def exit(self, status=0, message=None):
        if message:
            _say(message)
        sys.exit(status or EXIT_USAGE)  # --help verifies nothing, so it never exits 0


def main(argv=None):
    parser = _ArgumentParser(description="Verify a VOAF 2.x document (spec release 2.1.0, "
                                         "format tag voaf-2.0).")
    parser.add_argument("document", help='path to the document, or "-" for standard input')
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--genesis", metavar="HEX", help="a genesis known from outside the "
                        "document; a document genesis that differs is reported, but the verdict "
                        "follows the document's own genesis (section 7)")
    source.add_argument("--install-nonce", metavar="HEX", help="the 32-byte install nonce as "
                        "64 hex digits, from which that genesis is computed (section 5)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    genesis = genesis_source = None
    if args.install_nonce is not None:
        if not re.match(r"[0-9a-fA-F]{64}\Z", args.install_nonce):
            _say("error: --install-nonce takes 64 hex digits (32 bytes)\n")
            return EXIT_USAGE
        genesis = genesis_from_nonce(bytes.fromhex(args.install_nonce))
        genesis_source = "--install-nonce"
    elif args.genesis is not None:
        genesis, genesis_source = args.genesis, "--genesis"
    try:
        if args.document == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(args.document, "rb") as f:
                data = f.read()
    except OSError as e:
        _say("error: cannot read %s: %s\n" % (esc(args.document), e.strerror))
        return EXIT_USAGE
    rep = verify_bytes(data, genesis, genesis_source)
    sys.stdout.write((report_json(rep) if args.json else render(rep, args.document)) + "\n")
    sys.stdout.flush()  # inside the caller's handler, so a broken pipe exits 11
    return rep.exit_code


def _run():
    """main() with every failure mapped to a documented exit code: a crash, or a report
    that could not be written, exits 11 and never reads as a verdict."""
    try:
        return main()
    except SystemExit as e:
        return e.code if type(e.code) is int else EXIT_USAGE
    except Exception as e:
        _say("internal error: %s\n" % type(e).__name__)
        return EXIT_INTERNAL


if __name__ == "__main__":
    code = _run()
    try:
        sys.stdout.flush()
    except Exception:
        code = EXIT_INTERNAL
    os._exit(code)  # skip interpreter-exit flushes that could replace the code
