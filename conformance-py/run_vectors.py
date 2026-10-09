#!/usr/bin/env python3
"""Run every vector in spec/2.0/test-vectors.json against voaf_verify.py.

Prints one PASS or FAIL line per vector (vectors, negative_vectors and
negative_documents), and one each for the genesis cases, the chain walk and the
field-count table. A second block, "derived", checks spec rules no vector
exercises, using documents built from the vectors' own records; those lines are
not vectors. Exits 1 if any line fails.

Every document built here is verified in process and through the voaf_verify.py
command line (document on standard input), both with --json and as the report
for a person. All must agree; the exit code must be the one NOTES.md section 1
gives the verdict, and 0 only for `verified`. Nothing is written to disk.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True  # leave no __pycache__ beside the files
import voaf_verify as V  # noqa: E402

VECTORS = os.path.join(HERE, "spec", "2.0", "test-vectors.json")
VERIFIER = os.path.join(HERE, "voaf_verify.py")

# Section 8.1, negative_vectors[].stored_hash: which copy of a repeated name the
# reader that computes stored_hash keeps.
KEEPS = {"neg_duplicate_member": "last", "neg_duplicate_member_mirror": "first"}
# NOTES.md section 1, written out here so that a changed table fails the run.
EXPECTED_EXIT = {"verified": 0, "broken": 1, "truncated": 2, "empty": 3, "rejected": 6,
                 "1.0-linkage-only": 7, "1.0-link-broken": 8, "1.0-empty": 9}
# Section 7's code table (lines 1060-1087), written out independently of voaf_verify.
CODE_VERDICT = {"invalid_json": "rejected", "duplicate_member": "rejected",
                "unrecognised_format": "rejected", "format_mismatch": "rejected",
                "missing_member": "rejected", "malformed_member": "rejected",
                "unknown_member": "broken", "missing_field": "broken", "wrong_type": "broken",
                "null_field": "broken", "null_element": "broken", "over_limit": "broken",
                "unknown_kind": "broken", "feature_arity": "broken", "hash_mismatch": "broken",
                "link_break": "broken", "duplicate_seq": "broken",
                "anchor_head_mismatch": "broken", "root_missing": "truncated",
                "root_not_chain_upgrade": "truncated", "root_genesis_mismatch": "truncated",
                "seq_gap": "truncated", "anchor_exceeds_records": "truncated",
                "anchor_absent": None, "anchor_null": None, "anchor_unreadable": None}
# Section 4.4.1's table, written out independently of voaf_verify.
PAIRS = {("allow", "allow"): "allow", ("hold", "allow"): "allow",
         ("hold", "user_approve"): "allow", ("hold", "always_allow"): "allow",
         ("hold", "user_deny"): "not_allow", ("hold", "timeout_deny"): "not_allow",
         ("hold", "client_disconnected"): "not_allow", ("hold", "shutdown_deny"): "not_allow",
         ("hold", "connection_panicked"): "not_allow", ("allow", "restore"): "not_allow"}
# Section 8 criterion 5, and the notes that say "MUST hash differently".
MUST_DIFFER = {"interaction_empty_vs_null": "interaction_minimal",
               "interaction_content_off": "interaction_minimal",
               "interaction_second_conversation": "interaction_full_nonascii"}


class Fail(Exception):
    pass


def need(cond, message):
    if not cond:
        raise Fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def short(h):
    return h[:12] + "..." if type(h) is str else repr(h)


def num(v):
    text = V.int_text(v)
    need(text is not None, "%r is not an integer" % (v,))
    return int(text)


def expand_repeat(value):
    """Section 4.2.1: the vectors-file directive, expanded in vectors[].record only."""
    if type(value) is not dict:
        return value
    need(list(value) == ["$repeat"], "an object field value is not exactly one $repeat member")
    d = value["$repeat"]
    need(type(d) is dict and sorted(d) == ["char", "count"],
         "$repeat does not hold exactly char and count")
    char, count = d["char"], d["count"]
    need(type(char) is str and len(char) == 1 and not 0xD800 <= ord(char) <= 0xDFFF,
         "$repeat char is not one Unicode scalar value")
    need(num(count) >= 0, "$repeat count is negative")
    return char * num(count)


def loaded(vector):
    return {name: expand_repeat(value) for name, value in vector["record"].items()}


def table(kind):
    return V.ENVELOPE + V.KINDS[kind]


def lenient_parts(rec, tag=V.TAG, count=None, retype=None):
    """The preimage fields a reader without the section 7 rule 1 checks builds (the
    reader section 8.1 says computes stored_hash): an absent field read as NULL, a NULL
    anywhere written as 0x00, a $repeat object expanded, members outside the table
    ignored, `hash` never read, a field over a limit written with the header it finds,
    and a string in an integer field written with the integer marker. `retype` swaps
    a field's declared type."""
    kind = rec["event_kind"]
    parts = [V.encode_value(V.STR, tag),
             V.encode_value(V.INT, V.FIELD_COUNT[kind] if count is None else count)]
    for name, ftype, _ in table(kind):
        value = rec.get(name)
        if type(value) is dict:
            value = expand_repeat(value)
        ftype = (retype or {}).get(name, ftype)
        if ftype == V.INT and type(value) is str:  # the marker from the declared type
            payload = value.encode("utf-8")
            parts.append(bytes((2,)) + len(payload).to_bytes(4, "big") + payload)
        else:  # a field over a limit: the header it finds, unchecked
            parts.append(V.encode_value(ftype, value))
    return parts


def lenient_hash(rec, **kw):
    return sha256(b"".join(lenient_parts(rec, **kw)))


def as_decoded(ftype, v):
    """A record value as decode_preimage returns it."""
    if v is None:
        return None
    if isinstance(ftype, tuple):
        return ("array", [as_decoded(ftype[1], e) for e in v])
    return (ftype, V.int_text(v) if ftype == V.INT else v)


def doc_bytes(record_texts, genesis, anchor):
    """A 2.x document with the four members section 7 defines (lines 878-889):
    voaf_version, records, genesis and, when given, anchor."""
    text = '{"voaf_version": "2.0", "genesis": %s, ' % V.dump_json(genesis)
    if anchor is not None:
        text += '"anchor": {"entry_count": %d, "head_hash": %s}, ' % (anchor[0],
                                                                      V.dump_json(anchor[1]))
    return (text + '"records": [' + ", ".join(record_texts) + "]}").encode("utf-8")


def cli(data, args):
    return subprocess.run([sys.executable, "-I", VERIFIER] + args, input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def verify_both(data, genesis=None, cli_args=()):
    """Verify in process and through the command line, as JSON and as the report for a
    person. All must agree; the exit code must be NOTES.md's for the verdict, and the
    verdict must be the one section 7's code table gives the codes reported."""
    source = next((a for a in cli_args if a in ("--genesis", "--install-nonce")), None)
    rep = V.verify_bytes(data, genesis, source)
    need(rep.verdict in EXPECTED_EXIT, "unknown verdict %r" % rep.verdict)
    code = EXPECTED_EXIT[rep.verdict]
    need(V.EXIT[rep.verdict] == code, "voaf_verify.EXIT gives %s exit %d, NOTES.md %d"
         % (rep.verdict, V.EXIT[rep.verdict], code))
    if rep.format == "2.x" or rep.verdict == "rejected":   # section 7 lines 1029-1031
        verdicts = {CODE_VERDICT[c] for c in rep.codes}
        want = ("rejected" if "rejected" in verdicts else "broken" if "broken" in verdicts
                else "truncated" if "truncated" in verdicts
                else "empty" if rep.records == 0 else "verified")
        need(rep.verdict == want, "codes %s give %s, the verifier says %s"
             % (sorted(rep.codes), want, rep.verdict))
        need(rep.verdict != "rejected" or len(rep.codes) == 1,
             "a rejected document reports more than one code: %s" % sorted(rep.codes))
    args = ["-"] + list(cli_args)
    proc = cli(data, args + ["--json"])
    need(proc.returncode == code and (code == 0) == (rep.verdict == "verified"),
         "CLI exited %d for verdict %s (stderr %r)" % (proc.returncode, rep.verdict,
                                                       proc.stderr[:200]))
    out = json.loads(proc.stdout.decode("ascii"))
    need(out["verdict"] == rep.verdict and out["exit_code"] == code and
         [(f["index"], f["code"]) for f in out["findings"]] ==
         [(f["index"], f["code"]) for f in rep.findings] and
         sorted(out["codes"]) == sorted(rep.codes) and
         out["findings_omitted"] == rep.omitted and out["gate_decisions"] == rep.gate,
         "the CLI's JSON report differs from the in-process report")
    human = cli(data, args)
    text = human.stdout.decode("ascii", "replace")
    last = text.rstrip("\n").split("\n")[-1]
    need(human.returncode == code and human.stdout.isascii() and
         not re.search(r"[\x00-\x09\x0b-\x1f\x7f]", text) and
         re.match(r"verdict +%s \(exit %d\)\Z" % (re.escape(rep.verdict), code), last),
         "the report for a person ends %r, exit %d" % (last[-80:], human.returncode))
    return rep


def findings(rep):
    return {(f["index"], f["code"]) for f in rep.findings}


def main_findings(rep):
    """The findings that are not informational anchor codes."""
    return {(f["index"], f["code"]) for f in rep.findings if f["code"] not in V.INFORMATIONAL}


def ordered(pairs):
    return sorted(pairs, key=lambda p: (-1 if p[0] is None else p[0], p[1]))


def show(rep):
    return "%s %s" % (rep.verdict, ordered(findings(rep)))


class Suite:
    def __init__(self, vf):
        self.vf = vf
        self.vectors = vf["vectors"]
        self.by_name = {v["name"]: v for v in self.vectors}
        cases = vf["genesis"]["cases"]
        self.chain_case = cases[num(vf["chain"]["genesis_case_index"])]
        self.genesis = self.chain_case["expected_genesis"]
        members = sorted((v for v in self.vectors if v["chain_member"] is True),
                         key=lambda v: num(v["record"]["seq"]))
        self.chain = [dict(loaded(v), hash=v["expected_hash"]) for v in members]
        self.chain_names = [v["name"] for v in members]
        self.chain_texts = [V.dump_json(r) for r in self.chain]

    def chain_with(self, seq, text):
        """The chain's documents texts with the record at `seq` replaced by `text`."""
        return [text if i == seq else t for i, t in enumerate(self.chain_texts)]

    def full_anchor(self):
        return len(self.chain), self.chain[-1]["hash"]

    # --- genesis, chain, field counts -------------------------------------------

    def genesis_case(self, case):
        nonce = bytes.fromhex(case["install_nonce_hex"])
        need(len(nonce) == 32, "the nonce is %d bytes, not 32" % len(nonce))
        got = V.genesis_from_nonce(nonce)
        need(got == case["expected_genesis"], "computed %s, expected %s"
             % (got, case["expected_genesis"]))
        return "SHA256(b\"vigil-genesis\" || nonce) = %s" % short(got)

    def chain_walk(self):
        spec = self.vf["chain"]
        seqs = [num(r["seq"]) for r in self.chain]
        need(seqs == list(range(len(seqs))), "chain_member seqs are %s, not 0..n-1" % seqs)
        need(len(self.chain) == num(spec["entry_count"]), "%d chain members, entry_count %s"
             % (len(self.chain), num(spec["entry_count"])))
        need(self.chain[0]["prev_hash"] == self.genesis, "record 0 prev_hash is not the genesis")
        data = doc_bytes(self.chain_texts, self.genesis,
                         (num(spec["entry_count"]), spec["head_hash"]))
        rep = verify_both(data)
        need(rep.verdict == "verified" and not rep.findings, "verdict %s" % show(rep))
        need(rep.walked == rep.records == num(spec["entry_count"]),
             "walked %d of %d records" % (rep.walked, rep.records))
        need(rep.head == spec["head_hash"] and rep.unanchored_tail == 0,
             "head %s, expected %s" % (rep.head, spec["head_hash"]))
        nonce = self.chain_case["install_nonce_hex"]
        wrong = doc_bytes(self.chain_texts, "0" * 64, (num(spec["entry_count"]),
                                                     spec["head_hash"]))
        rep2 = verify_both(wrong)
        need(findings(rep2) == {(0, "root_genesis_mismatch")} and rep2.verdict == "truncated",
             "with a wrong document genesis: %s" % show(rep2))
        rep2 = verify_both(wrong, V.genesis_from_nonce(bytes.fromhex(nonce)),
                           ["--install-nonce", nonce])
        need(rep2.verdict == "truncated" and any("--install-nonce" in t for t in rep2.notes),
             "wrong document genesis, --install-nonce: %s %s" % (show(rep2), rep2.notes))
        rep3 = verify_both(data, V.genesis_from_nonce(bytes.fromhex(nonce)),
                           ["--install-nonce", nonce])
        need(rep3.verdict == "verified" and not rep3.notes, "--install-nonce: %s" % show(rep3))
        bare = doc_bytes(self.chain_texts, self.genesis, None)
        rep4 = verify_both(bare)
        need(rep4.verdict == "verified" and findings(rep4) == {(None, "anchor_absent")},
             "without an anchor: %s" % show(rep4))
        short_doc = doc_bytes(self.chain_texts[:-1], self.genesis,
                              (num(spec["entry_count"]), spec["head_hash"]))
        rep6 = verify_both(short_doc)
        need(findings(rep6) == {(None, "anchor_exceeds_records")} and
             rep6.verdict == "truncated", "last record dropped: %s" % show(rep6))
        return ("walked %d chain_member records (%s .. %s) from genesis case %d; head %s, "
                "entry_count %d; verified, exit 0, with chain.head_hash/entry_count as the "
                "anchor; with no anchor, verified with anchor_absent; a wrong document genesis "
                "is truncated, exit 2, whatever --install-nonce says; last record dropped: "
                "truncated, exit 2" % (len(self.chain), self.chain_names[0],
                                       self.chain_names[-1], num(spec["genesis_case_index"]),
                                       short(rep.head), rep.records))

    def field_counts(self):
        got = {k: num(v) for k, v in self.vf["field_counts"].items()}
        need(got == V.FIELD_COUNT, "vectors file %s, section 2.2 %s" % (got, V.FIELD_COUNT))
        return "matches the section 2.2 table"

    # --- positive vectors -----------------------------------------------------------

    def positive(self, v):
        rec = loaded(v)
        kind = v["event_kind"]
        need(rec.get("event_kind") == kind, "record.event_kind differs from vectors[].event_kind")
        need("hash" not in v["record"], "vectors[].record carries a hash member")
        res = V.check_record(rec, require_hash=False)
        need(not res.problems, "the record does not decode: %s" % res.problems[:3])
        pre = res.preimage
        need(len(pre) == num(v["preimage_len"]), "preimage is %d bytes, preimage_len %s"
             % (len(pre), num(v["preimage_len"])))
        need(sha256(pre) == v["preimage_sha256"], "preimage SHA256 %s, preimage_sha256 %s"
             % (sha256(pre), v["preimage_sha256"]))
        need(res.computed == v["expected_hash"], "hash %s, expected_hash %s"
             % (res.computed, v["expected_hash"]))
        if v["preimage_hex"] is None:
            need(len(pre) > 4096, "preimage_hex is null for a %d-byte preimage" % len(pre))
            said = ["preimage_hex null (%d bytes > 4096), preimage_sha256 matches" % len(pre)]
        else:
            need(len(pre) <= 4096, "preimage_hex given for a %d-byte preimage" % len(pre))
            if pre.hex() != v["preimage_hex"]:
                want = bytes.fromhex(v["preimage_hex"])
                at = next((i for i in range(min(len(pre), len(want))) if pre[i] != want[i]),
                          min(len(pre), len(want)))
                raise Fail("preimage differs from preimage_hex at byte %d" % at)
            said = ["preimage_hex matches (%d bytes)" % len(pre)]
        expected_fields = ([(V.STR, V.TAG), (V.INT, str(V.FIELD_COUNT[kind]))]
                           + [as_decoded(t, rec[n]) for n, t, _ in table(kind)])
        need(V.decode_preimage(pre) == expected_fields,
             "the preimage does not read back as the record's fields")
        if "substituted_field" in v:                                  # criterion 5
            field = v["substituted_field"]
            swapped = lenient_hash(dict(rec, **{field: ""}), retype={field: V.STR})
            need(swapped == v["expected_hash_if_rule_ids_were_empty_string"],
                 "%s as an empty string hashes %s, vector says %s"
                 % (field, swapped, v["expected_hash_if_rule_ids_were_empty_string"]))
            need(v["must_differ"] is True and swapped != v["expected_hash"],
                 "the substituted hash does not differ")
            third = lenient_hash(dict(rec, snapshot_ids=""), retype={"snapshot_ids": V.STR})
            need(third not in (swapped, v["expected_hash"]),
                 "snapshot_ids substituted does not give a third hash")
            said.append("%s as \"\" gives %s, which differs; snapshot_ids gives a third"
                        % (field, short(swapped)))
        if v["name"] in MUST_DIFFER:
            other = self.by_name[MUST_DIFFER[v["name"]]]["expected_hash"]
            need(v["expected_hash"] != other, "hash equals %s" % MUST_DIFFER[v["name"]])
            said.append("differs from %s" % MUST_DIFFER[v["name"]])
        seq = num(rec["seq"])                                         # in a chain
        texts = self.chain_texts[:seq] + [V.dump_json(dict(rec, hash=v["expected_hash"]))]
        rep = verify_both(doc_bytes(texts, self.genesis, (seq + 1, v["expected_hash"])))
        need(rep.verdict == "verified" and not rep.findings,
             "as the head of chain records 0..%d: %s" % (seq, show(rep)))
        said.append("verified as head of a %d-record chain%s (exit 0)"
                    % (seq + 1, "" if v["chain_member"] else ", a fork"))
        return "hash %s; %s" % (short(res.computed), "; ".join(said))

    # --- negative vectors -----------------------------------------------------------

    def negative(self, v):
        if "record" in v:
            return self.negative_record(v)
        if "record_json" in v:
            return self.negative_record_json(v)
        if "document" in v:
            return self.negative_document(v)
        mutation = v["mutation"]
        for pattern, check in ((r"format tag changed to (\S+)\Z", self.mutated_tag),
                               (r"field count changed from (\d+) to (\d+)\Z", self.mutated_count),
                               (r"(\w+) declares a u32be length of (\d+)", self.over_length),
                               (r"(\w+) declares a u32be count of (\d+)", self.over_count)):
            m = re.match(pattern, mutation)
            if m:
                return check(v, self.by_name[v["basis"]], m)
        raise Fail("mutation not understood: %r" % mutation)

    def in_chain(self, seq, text, expect):
        """Verify the chain with the record at `seq` replaced; findings must equal `expect`."""
        rep = verify_both(doc_bytes(self.chain_with(seq, text), self.genesis, self.full_anchor()))
        need(findings(rep) == expect and rep.verdict == "broken",
             "in the chain: %s, expected broken %s" % (show(rep), ordered(expect)))
        return rep

    def mutated_hash(self, v, basis, tag=V.TAG, count=None):
        rec = loaded(basis)
        res = V.check_record(rec, require_hash=False, tag=tag, field_count=count)
        need(res.computed == v["expected_hash"], "mutated preimage hashes %s, expected_hash %s"
             % (res.computed, v["expected_hash"]))
        need(v["must_differ_from"] == basis["expected_hash"] != v["expected_hash"],
             "must_differ_from is not the basis hash, or equals expected_hash")
        need(V.decode_preimage(res.preimage)[:2] ==
             [(V.STR, tag), (V.INT, str(V.FIELD_COUNT[rec["event_kind"]] if count is None
                                       else count))], "the mutated preimage does not read back")
        bad = dict(rec, hash=v["expected_hash"])
        seq = num(rec["seq"])
        rep = self.in_chain(seq, V.dump_json(bad), {(seq, "hash_mismatch"),
                                                     (seq + 1, "link_break")})
        return ("hash moves to %s (differs from %s); a record carrying it fails at index %d "
                "with hash_mismatch: %s, exit %d"
                % (short(res.computed), short(basis["expected_hash"]), seq, rep.verdict,
                   rep.exit_code))

    def mutated_tag(self, v, basis, m):
        return self.mutated_hash(v, basis, tag=m.group(1))

    def mutated_count(self, v, basis, m):
        need(int(m.group(1)) == V.FIELD_COUNT[basis["event_kind"]],
             "the basis count is not %s" % m.group(1))
        return self.mutated_hash(v, basis, count=int(m.group(2)))

    def over_limit(self, v, basis, field, too_big, at_limit, marker, declared, payload):
        """Shared by the two revision 3 over-limit vectors, which name no violation:
        section 7 rule 1 gives over_limit."""
        rec = loaded(basis)
        kind, seq = rec["event_kind"], num(rec["seq"])
        names = [n for n, _, _ in table(kind)]
        need(field in names, "%s is not a %s field" % (field, kind))
        res = V.check_record(dict(rec, **{field: at_limit}), require_hash=False)
        need(not res.problems, "exactly at the limit: %s" % res.problems[:2])
        bad = dict(rec, **{field: too_big}, hash=basis["expected_hash"])
        codes = {c for c, _ in V.check_record(bad).problems}
        need(codes == {"over_limit"}, "check_record reports %s" % sorted(codes))
        parts = lenient_parts(rec)
        i = 2 + names.index(field)
        at = b"".join(parts[:i] + [bytes((marker,)) + (declared - 1).to_bytes(4, "big")
                                   + payload[:len(payload) * (declared - 1) // declared]]
                      + parts[i + 1:])
        V.decode_preimage(at)  # the raw header exactly at the limit decodes
        for body in (payload, b""):  # the header alone must fail, before any payload
            data = b"".join(parts[:i] + [bytes((marker,)) + declared.to_bytes(4, "big") + body]
                            + parts[i + 1:])
            try:
                V.decode_preimage(data)
                raise Fail("decode_preimage accepted a header of %d" % declared)
            except V.PreimageError as e:
                need(e.code == "over_limit", "decode_preimage: %s" % e)
        rep = self.in_chain(seq, V.dump_json(bad), {(seq, "over_limit")})
        return ("over_limit: the document field (in the chain at index %d: %s, exit %d), and the "
                "raw u32be header %d with and without its payload; exactly at the limit, both "
                "the document field and the raw header decode"
                % (seq, rep.verdict, rep.exit_code, declared))

    def over_length(self, v, basis, m):
        field, n = m.group(1), int(m.group(2))
        need(n == V.MAX_FIELD_BYTES + 1, "declared length %d is not 2^20 + 1" % n)
        return self.over_limit(v, basis, field, "A" * n, "A" * V.MAX_FIELD_BYTES, 1, n, b"A" * n)

    def over_count(self, v, basis, m):
        field, n = m.group(1), int(m.group(2))
        need(n == V.MAX_ARRAY_ELEMENTS + 1, "declared count %d is not 2^16 + 1" % n)
        element = V.encode_value(V.STR, "x")
        return self.over_limit(v, basis, field, ["x"] * n, ["x"] * V.MAX_ARRAY_ELEMENTS, 4, n,
                               element * n)

    def basis_diff(self, v, rec):
        """The members in which a record-form vector differs from its basis record, which
        carries no hash; a string hash is expected, so only a non-string one is listed."""
        base = self.by_name[v["basis"]]["record"]
        changed = [n for n in sorted(set(base) | set(rec)) if n != "hash" and
                   (n not in base or n not in rec or base[n] != rec[n])]
        return changed + ([] if type(rec.get("hash")) is str else ["hash"])

    def negative_record(self, v):
        rec, violation = v["record"], v["violation"]  # never expanded (section 4.2.1)
        acceptable = v.get("acceptable_violations", [violation])
        need(violation in acceptable, "violation is not among acceptable_violations")
        res = V.check_record(rec)
        codes = [c for c, _ in res.problems]
        need(codes == [violation], "check_record reports %s, the vector names %s"
             % (codes, violation))
        if "expected_hash" in v:   # neg_decision_edited_without_rehash: rule 3
            need(rec["hash"] == v["stored_hash"], "record.hash is not stored_hash")
            need(res.computed == v["expected_hash"] != v["stored_hash"],
                 "recompute gives %s, expected_hash %s" % (res.computed, v["expected_hash"]))
            need(v["must_differ_from"] == v["stored_hash"], "must_differ_from is not stored_hash")
            oracle = "recompute gives expected_hash %s" % short(res.computed)
        else:                      # what a reader without the check computes (8.1)
            if type(rec.get("hash")) is str:
                need(rec["hash"] == v["stored_hash"], "record.hash is not stored_hash")
            got = lenient_hash(rec)
            need(got == v["stored_hash"], "a reader without the %s check computes %s, "
                 "stored_hash is %s" % (violation, got, v["stored_hash"]))
            oracle = "a reader without the check computes stored_hash %s" % short(got)
        seq = num(rec["seq"])
        expect = {(seq, violation)}
        if (type(rec.get("hash")) is str and rec["hash"] != self.chain[seq]["hash"]
                and seq + 1 < len(self.chain)):
            expect.add((seq + 1, "link_break"))  # the record after it no longer links
        rep = self.in_chain(seq, V.dump_json(rec), expect)
        need(rep.verdict == "broken", "verdict %s" % rep.verdict)
        return ("%s at index %d (differs from %s in: %s); %s; in the chain: %s, exit %d"
                % (violation, seq, v["basis"], ", ".join(self.basis_diff(v, rec)), oracle,
                   show(rep), rep.exit_code))

    def negative_record_json(self, v):
        text, violation = v["record_json"], v["violation"]
        try:
            V.parse_json(text)
            raise Fail("record_json parsed without complaint")
        except V.Rejected as e:
            need(e.code == violation, "parse_json reports %s, the vector names %s"
                 % (e.code, violation))
        keep = KEEPS.get(v["name"])
        need(keep is not None, "section 8.1 does not say which copy this vector's reader keeps")
        hook = None if keep == "last" else (lambda pairs: dict(reversed(pairs)))
        rec = json.loads(text, parse_int=V.JInt, object_pairs_hook=hook)
        need(rec["hash"] == v["stored_hash"], "record hash is not stored_hash")
        got = lenient_hash(rec)
        need(got == v["stored_hash"], "a parser keeping the %s copy computes %s, stored_hash %s"
             % (keep, got, v["stored_hash"]))
        seq = num(rec["seq"])
        rep = verify_both(doc_bytes(self.chain_with(seq, text), self.genesis, self.full_anchor()))
        need(rep.verdict == "rejected" and [f["code"] for f in rep.findings] == [violation],
             "in the chain: %s" % show(rep))
        return ("%s while parsing; a parser keeping the %s copy computes stored_hash %s; in the "
                "chain: rejected, no record walked, exit %d"
                % (violation, keep, short(got), rep.exit_code))

    def negative_document(self, v):
        doc, violation = v["document"], v["violation"]
        need(violation in v.get("acceptable_violations", [violation]),
             "violation is not among acceptable_violations")
        rep = verify_both(V.dump_json(doc).encode("utf-8"))
        need(rep.verdict == "rejected" and [f["code"] for f in rep.findings] == [violation],
             "verifier: %s" % show(rep))
        entries = doc["interactions"]
        readme = list(V.v1_link_walk(entries))
        vigil = list(V.v1_link_walk(entries, anchor=None))
        need([(k, c) for k, c, _ in readme] == [(0, "link_break")],
             "a 1.0 walk anchored at the all-zero hash gives %s" % readme)
        need(vigil == [], "a 1.0 walk that does not anchor entry 0 gives %s" % vigil)
        altered = [i for i, e in enumerate(entries)
                   if {c for c, _ in V.check_record(e).problems} == {"hash_mismatch"}]
        edited = [i for i, e in enumerate(entries) if e != self.chain[num(e["seq"])]]
        need(edited and altered == edited, "entries %s differ from the chain, but a 2.x walk "
             "flags %s" % (edited, altered))
        restored = [dict(e) for e in entries]
        for i in edited:
            restored[i] = {k: v for k, v in self.chain[num(entries[i]["seq"])].items()}
        need([(k, c) for k, c, _ in V.v1_link_walk(restored)] == [(0, "link_break")],
             "the unedited relabelled document does not fail the zero-anchored walk alike")
        return ("%s before any record (exit %d); expected_outcome confirmed: a zero-anchored 1.0 "
                "walk gives link_break at entry 0, with record 2 edited or not; an unanchored one "
                "passes; only a 2.x walk finds the edit, hash_mismatch at entry %s"
                % (violation, rep.exit_code, altered))

    # --- negative documents ---------------------------------------------------------

    def negative_doc(self, v):
        want_verdict, want_codes = v["expected_verdict"], v["expected_codes"]
        need(len(set(want_codes)) == len(want_codes), "expected_codes repeats a code")
        need(all(c in CODE_VERDICT for c in want_codes), "a code section 7 does not give")
        if "document_json" in v:
            data = v["document_json"].encode("utf-8")
            copies = []   # every copy of a repeated member, to check each one's records
            json.loads(v["document_json"], parse_int=V.JInt, parse_float=V.JNum,
                       object_pairs_hook=lambda pairs: copies.extend(pairs) or dict(pairs))
            record_lists = [val for key, val in copies if key == "records"]
        else:
            data = V.dump_json(v["document"]).encode("utf-8")
            doc = v["document"]
            record_lists = [doc.get("records")] if type(doc) is dict else []
        for records in record_lists:  # 8.1: no record fails rule 1, 2 or 3
            for rec in records if type(records) is list else []:
                codes = [c for c, _ in V.check_record(rec).problems]
                need(not codes, "a record fails rules 1 to 3 (%s), against 8.1 line 1252"
                     % codes)
        rep = verify_both(data)
        need(rep.verdict == want_verdict and rep.codes == set(want_codes),
             "verifier: %s, codes %s; expected %s, codes %s"
             % (rep.verdict, sorted(rep.codes), want_verdict, sorted(want_codes)))
        return ("%s with codes %s, exactly as expected (exit %d); %d records, none failing "
                "rules 1 to 3" % (rep.verdict, ", ".join(sorted(rep.codes)), rep.exit_code,
                                  sum(len(r) for r in record_lists if type(r) is list)))


class Doc(bytes):
    """Document bytes that carry the informational anchor codes their anchor gives."""
    info = frozenset()


class Derived:
    """Spec rules that no vector exercises, checked on documents built from the vectors'
    own records. These lines are not vectors and are counted separately."""

    def __init__(self, suite):
        self.s = suite
        self.G = suite.genesis
        picked = [suite.chain[i] for i in (0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12)]
        self.base = self.relink([dict(r, seq=V.JInt(str(i))) for i, r in enumerate(picked)])
        self.n = len(self.base)
        self.full = (self.n, self.base[-1]["hash"])

    def seal(self, rec):
        """rec with `hash` recomputed; a record that does not decode gets a placeholder."""
        body = {k: v for k, v in rec.items() if k != "hash"}
        res = V.check_record(body, require_hash=False)
        return dict(body, hash=res.computed or sha256(V.dump_json(body, True).encode()))

    def relink(self, recs):
        out, before = [], self.G
        for r in recs:
            r = self.seal(dict(r, prev_hash=before))
            out.append(r)
            before = r["hash"]
        return out

    def doc(self, recs, genesis=True, anchor=None, raw_anchor=None, version='"2.0"',
            info=None):
        parts = ['"voaf_version": %s' % version]
        if genesis is True:
            parts.append('"genesis": %s' % json.dumps(self.G))
        elif genesis is not False:
            parts.append('"genesis": %s' % json.dumps(genesis))
        if anchor is not None:
            parts.append('"anchor": {"entry_count": %d, "head_hash": %s}'
                         % (anchor[0], json.dumps(anchor[1])))
        if raw_anchor is not None:
            parts.append('"anchor": ' + raw_anchor)
        parts.append('"records": [%s]' % ", ".join(V.dump_json(r, True) for r in recs))
        data = Doc(("{" + ", ".join(parts) + "}").encode("ascii"))
        data.info = frozenset(info if info is not None else
                              () if anchor is not None or raw_anchor is not None
                              else ("anchor_absent",))
        return data

    def expect(self, data, verdict, found=(), info=None, **kw):
        rep = verify_both(data, **kw)
        if info is None:
            info = () if verdict == "rejected" else getattr(data, "info", ())
        got_info = rep.codes & V.INFORMATIONAL
        need(rep.verdict == verdict and main_findings(rep) == set(found) and
             got_info == set(info),
             "got %s, expected %s %s with %s" % (show(rep), verdict, ordered(found),
                                                 sorted(info)))
        return rep

    def edited(self, k, **fields):
        recs = [dict(r) for r in self.base]
        recs[k].update(fields)
        return recs

    def checks(self):
        return [
            ("seq order", "lines 915-916", self.seq_order),
            ("record 0 and the genesis", "lines 885, 891-896, 986-990", self.root),
            ("deletion, gap and duplicate seq", "lines 974-977, 984-997", self.gaps),
            ("rules 3 and 4 in a 2.x document", "lines 972-978, 1041-1045", self.links),
            ("stored hash absent or not a string", "lines 927-938", self.hash_member),
            ("unknown_kind and feature_arity", "lines 948-952", self.rule2),
            ("wrong types, NULLs and records outside the walk",
             "lines 123-125, 918-938, 1025-1029", self.types),
            ("per-preimage bound, inclusive", "lines 150-153, 951-952", self.preimage_bound),
            ("parse check and JSON edge cases", "lines 845-856", self.parsing),
            ("format check and document member check", "lines 858-896", self.formats),
            ("1.0 documents, link-only", "lines 1047-1050", self.v1),
            ("zero records", "lines 1000-1001, 1016-1019, 1137-1144", self.empty),
            ("carried anchor", "lines 886, 898-909, 998-1017", self.anchors),
            ("gate_decision allows by the pair", "lines 538-559, 962-968", self.gates),
            ("values the vectors never use", "lines 123, 133-136, 386-389, 570-572",
             self.unusual_values),
            ("escaping document strings", "lines 970-971", self.escaping),
            ("command line and exit codes", "NOTES.md section 1", self.command_line),
            ("very long integers and many failures", "lines 148, 918", self.scale),
        ]

    def seq_order(self):
        recs = list(reversed(self.base))
        rep = self.expect(self.doc(recs, anchor=self.full), "verified")
        need(rep.walked == self.n, "walked %d" % rep.walked)
        return "the records array reversed verifies: records are walked in ascending seq order"

    def root(self):
        lc = dict(self.s.chain[11], seq=V.JInt("0"))
        recs = self.relink([lc] + self.base[1:])
        self.expect(self.doc(recs), "truncated", {(0, "root_not_chain_upgrade")})
        self.expect(self.doc(self.base, genesis="1" * 64), "truncated",
                    {(0, "root_genesis_mismatch")})
        rep = self.expect(self.doc(self.base, genesis="1" * 64), "truncated",
                          {(0, "root_genesis_mismatch")}, genesis=self.G,
                          cli_args=["--genesis", self.G])
        need(any("--genesis" in t for t in rep.notes), "the supplied genesis is not reported")
        self.expect(self.doc(self.base, genesis=False), "rejected", {(None, "missing_member")})
        self.expect(self.doc(self.base, genesis=None), "rejected", {(None, "missing_member")})
        self.expect(self.doc(self.base, genesis=5), "rejected", {(None, "malformed_member")})
        self.expect(self.doc(self.base[1:]), "truncated", {(0, "root_missing")})
        negative = self.relink([dict(r, seq=V.JInt(str(i - 1))) for i, r in enumerate(self.base)])
        self.expect(self.doc(negative), "truncated", {(0, "root_missing")})
        fork = self.seal(dict(self.base[0], id="fork"))               # two records at seq 0
        self.expect(self.doc([self.base[0], fork] + self.base[1:]), "broken",
                    {(1, "duplicate_seq")})
        bad_fork = self.seal(dict(lc, prev_hash=self.G))
        self.expect(self.doc([self.base[0], bad_fork] + self.base[1:]), "broken",
                    {(1, "duplicate_seq"), (1, "root_not_chain_upgrade")})
        return ("record 0 not a chain_upgrade, a wrong genesis, no seq 0 and a negative lowest "
                "seq are truncated, and every record at seq 0 is checked; no or a null genesis is "
                "missing_member and a non-string one malformed_member; --genesis only adds a note")

    def gaps(self):
        relinked = self.relink(self.base[:5] + self.base[6:])
        self.expect(self.doc(relinked), "truncated", {(5, "seq_gap")})
        self.expect(self.doc(self.base[:5] + self.base[6:]), "broken",
                    {(5, "seq_gap"), (5, "link_break")})
        fork = self.seal(dict(self.base[5], id="fork"))               # also links to seq 4
        dup = self.base[:6] + [fork] + self.base[6:]
        self.expect(self.doc(dup), "broken", {(6, "duplicate_seq")})
        dup_head = self.doc(dup, anchor=(len(dup), dup[-1]["hash"]))
        self.expect(dup_head, "broken", {(6, "duplicate_seq")})
        to_fork = self.doc(dup, anchor=(7, fork["hash"]))            # head names either copy
        rep = self.expect(to_fork, "broken", {(6, "duplicate_seq")})
        need(rep.unanchored_tail == len(dup) - 7, "tail %d" % rep.unanchored_tail)
        straight = self.relink(self.base[:6] + [dict(self.base[5])] + self.base[6:])
        self.expect(self.doc(straight), "broken", {(6, "duplicate_seq"), (6, "link_break")})
        outside = list(dup)
        outside[-1] = dict(outside[-1], seq="11")                     # no integer seq
        self.expect(self.doc(outside), "broken", {(6, "duplicate_seq"), (None, "wrong_type")})
        return ("a re-linked gap is truncated; a naive deletion is broken (seq_gap and link_break "
                "at the record after the hole); a duplicate seq is broken and not also a gap, and "
                "rule 4 and the head check accept any record at the repeated seq")

    def links(self):
        recs = self.edited(4)
        recs[4] = self.seal(dict(recs[4], timestamp_us=V.JInt("1750385896000001")))
        self.expect(self.doc(recs), "broken", {(5, "link_break")})
        recs = self.edited(4, timestamp_us=V.JInt("1750385896000001"))
        self.expect(self.doc(recs), "broken", {(4, "hash_mismatch")})
        return ("a record altered and re-hashed reports link_break at the next index; altered "
                "without re-hashing, hash_mismatch at its own")

    def hash_member(self):
        recs = self.edited(3)
        del recs[3]["hash"]
        self.expect(self.doc(recs), "broken", {(3, "missing_field")})
        self.expect(self.doc(self.edited(3, hash=None)), "broken", {(3, "null_field")})
        self.expect(self.doc(self.edited(3, hash=self.base[3]["hash"].upper())), "broken",
                    {(3, "hash_mismatch"), (4, "link_break")})
        return ("absent hash: missing_field; NULL hash: null_field (line 937); uppercase hash: "
                "hash_mismatch")

    def rule2(self):
        k = self.n - 1
        self.expect(self.doc(self.relink(self.base[:k] + [dict(self.base[k],
                                                              event_kind="transport")])),
                    "broken", {(k, "unknown_kind")})
        inter = dict(self.base[1], seq=V.JInt(str(k)))
        for size in (26, 28):
            short = dict(inter, features_canonical=[V.JInt("0")] * size)
            self.expect(self.doc(self.relink(self.base[:k] + [short])), "broken",
                        {(k, "feature_arity")})
        return "event_kind transport: unknown_kind; 26 or 28 features: feature_arity"

    def types(self):
        cases = [(7, "held_ms", "14320"), (7, "held_ms", True), (7, "held_ms", V.JNum("1.0")),
                 (1, "is_anomaly", V.JInt("0")), (7, "verdict", ["hold"]),
                 (7, "rule_ids", "R-003"), (1, "features_canonical", [[V.JInt("0")]] * 27),
                 (1, "timestamp_us", V.JInt("-0")), (1, "user_message", "\ud800")]
        for k, name, value in cases:
            self.expect(self.doc(self.edited(k, **{name: value})), "broken", {(k, "wrong_type")})
        self.expect(self.doc(self.edited(3, event_kind=None)), "broken", {(3, "null_field")})
        for k, name in ((1, "id"), (1, "timestamp_us"), (7, "prev_hash")):
            self.expect(self.doc(self.edited(k, **{name: None})), "broken", {(k, "null_field")})
        for value, code in ((None, "null_field"), ("2", "wrong_type"), (V.JNum("2.0"), "wrong_type")):
            rep = self.expect(self.doc(self.edited(2, seq=value)), "broken",
                              {(None, code), (2, "seq_gap"), (2, "link_break")})
            need(rep.walked == self.n - 1, "a record with no integer seq was walked")
        recs = list(self.base)
        recs[3] = ["not", "an", "object"]
        self.expect(self.doc(recs), "broken", {(None, "wrong_type"), (3, "seq_gap"),
                                               (3, "link_break")})
        recs[3] = None
        self.expect(self.doc(recs), "broken", {(None, "wrong_type"), (3, "seq_gap"),
                                               (3, "link_break")})
        return ("%d wrong types are wrong_type; NULL id, timestamp_us, prev_hash and event_kind "
                "are null_field; a record with no integer seq, or not an object (null included), "
                "has no place in the walk, which then shows a gap and a broken link" % len(cases))

    def preimage_bound(self):
        rec = {k: v for k, v in self.base[2].items() if k != "hash"}
        names = ["user_message", "ai_response", "model", "conversation_ref", "client_ref",
                 "user_message_sha256", "ai_response_sha256", "matched_policy", "block_reason",
                 "policy_id", "tap_certificate_id", "execution_gate_id", "provider", "scope",
                 "id", "action"]
        for name in names[:-1]:
            rec[name] = "B" * V.MAX_FIELD_BYTES
        size = len(V.check_record(rec, require_hash=False).preimage)
        rec[names[-1]] += "B" * (V.MAX_PREIMAGE_BYTES - size)
        at = V.check_record(rec, require_hash=False)
        need(len(at.preimage) == V.MAX_PREIMAGE_BYTES and not at.problems,
             "exactly 2^24 bytes: %s" % at.problems[:1])
        V.decode_preimage(at.preimage)
        try:
            V.decode_preimage(at.preimage + b"\x00")
            raise Fail("decode_preimage accepted 2^24 + 1 bytes")
        except V.PreimageError as e:
            need(e.code == "over_limit", str(e))
        recs = self.relink(self.base[:2] + [rec] + self.base[3:])
        self.expect(self.doc(recs), "verified")
        over = dict(rec, action=rec["action"] + "B")
        codes = [c for c, _ in V.check_record(over, require_hash=False).problems]
        need(codes == ["over_limit"], "2^24 + 1 bytes: %s" % codes)
        return ("a record whose preimage is exactly 2^24 bytes verifies in a chain; one byte "
                "more is over_limit, as a record and as raw bytes")

    def parsing(self):
        for text, code in ((b'{"voaf_version": "2.0", "voaf_version": "2.0", "records": []}',
                            "duplicate_member"),
                           (b'{"voaf_version": "2.0", "v\\u006faf_version": "2.0", "records": []}',
                            "duplicate_member"),
                           (b'{"voaf_version": "2.0", "records": [NaN]}', "invalid_json"),
                           (b'\xef\xbb\xbf{"voaf_version": "2.0", "records": []}', "invalid_json"),
                           (b'{"voaf_version": "2.0", "records": []} x', "invalid_json"),
                           (b'{"voaf_version": "2.0", "records": ["\xff"]}', "invalid_json"),
                           (b'{"voaf_version": "2.0", "records": ' + b"[" * 100000
                            + b"]" * 100000 + b"}", "invalid_json")):
            self.expect(text, "rejected", {(None, code)})
        deep = "[" * 600 + "]" * 600
        self.expect(self.doc(self.base, raw_anchor=deep, info=("anchor_unreadable",)),
                    "verified")
        self.expect(self.doc(self.base, version=deep), "rejected", {(None, "unrecognised_format")})
        return ("repeated names (also after unescaping), NaN, a BOM, trailing text, bad UTF-8 and "
                "nesting too deep are rejected; a deeply nested anchor is anchor_unreadable and "
                "shown without crashing")

    def formats(self):
        entry = {"prev_hash": "0" * 64, "hash": "a" * 64}
        for doc in ({"voaf_version": "1.0", "records": [], "interactions": []},
                    {"voaf_version": "1.0", "interactions": [dict(entry, timestamp_us=1)]},
                    [dict(entry, voaf="1.0", seq=0)]):
            self.expect(json.dumps(doc).encode(), "rejected", {(None, "format_mismatch")})
        for doc in ({"voaf_version": "3.0", "records": []}, {"records": []},
                    {"voaf_version": 2, "records": []}, {"voaf_version": "01.0", "records": []},
                    {"voaf_version": "02", "records": []}, {"voaf_version": "2.", "records": []},
                    {"voaf_version": "2..0", "records": []}, {"voaf_version": " 2.0", "records": []},
                    {"voaf_version": "voaf-2.0", "records": []}, [{"voaf": "2.0"}], "x"):
            self.expect(json.dumps(doc).encode(), "rejected", {(None, "unrecognised_format")})
        for doc, code in (({"voaf_version": "2.0"}, "missing_member"),
                          ({"voaf_version": "2.0", "records": None}, "missing_member"),
                          ({"voaf_version": "2.0", "records": "x"}, "malformed_member"),
                          ({"voaf_version": "2.0", "records": {}}, "malformed_member")):
            self.expect(json.dumps(doc).encode(), "rejected", {(None, code)})
        for version in ("2", "2.1.0", "2.0.0.0"):
            self.expect(self.doc(self.base, version=json.dumps(version), anchor=self.full),
                        "verified")
        return ("1.x with records or a 2.x entry member is format_mismatch; '01.0', '02', '2.', "
                "'voaf-2.0' and other versions not of section 7's form are unrecognised_format; "
                "no records is missing_member and a non-array malformed_member; '2', '2.1.0' "
                "and '2.0.0.0' declare 2.x")

    def v1(self):
        a, b = {"prev_hash": "0" * 64, "hash": "a" * 64}, {"prev_hash": "a" * 64, "hash": "b" * 64}
        self.expect(json.dumps({"voaf_version": "1.0", "interactions": [a, b]}).encode(),
                    "1.0-linkage-only")
        self.expect(json.dumps([dict(a, voaf="1.0"), dict(b, voaf="1"), ]).encode(),
                    "1.0-linkage-only")
        self.expect(json.dumps({"voaf_version": "1.0", "interactions": [b, a]}).encode(),
                    "1.0-link-broken", {(0, "link_break"), (1, "link_break")})
        self.expect(json.dumps({"voaf_version": "1.0", "interactions": [a, {}]}).encode(),
                    "1.0-link-broken", {(1, "malformed_entry")})
        self.expect(b'{"voaf_version": "1.0", "interactions": []}', "1.0-empty")
        self.expect(b'[]', "1.0-empty")
        need(not set(EXPECTED_EXIT[v] for v in ("1.0-linkage-only", "1.0-link-broken",
                                                 "1.0-empty")) &
             set(EXPECTED_EXIT[v] for v in EXPECTED_EXIT if not v.startswith("1.0")),
             "a 1.0 exit code is shared with a 2.x verdict")
        return ("both 1.0 shapes, an empty top-level array included, walk link-only with their "
                "own verdicts and exit codes 7, 8, 9")

    def empty(self):
        self.expect(self.doc([]), "empty")
        self.expect(self.doc([], genesis=False), "empty")
        self.expect(self.doc([], genesis=5), "empty")
        self.expect(self.doc([], anchor=(0, "x")), "empty")
        self.expect(self.doc([], anchor=(5, "x")), "truncated", {(None, "anchor_exceeds_records")})
        self.expect(self.doc([], raw_anchor='{"entry_count": 5}'), "truncated",
                    {(None, "anchor_exceeds_records")})
        self.expect(self.doc([], raw_anchor="null", info=("anchor_null",)), "empty")
        self.expect(self.doc([], raw_anchor='{"unreadable": true}', info=("anchor_unreadable",)),
                    "empty")
        return ("zero records: empty whatever the genesis holds, with the anchor's informational "
                "code; truncated when the anchor counts records; nothing more with entry_count 0")

    def anchors(self):
        n, hashes = self.n, [r["hash"] for r in self.base]
        d = lambda **kw: self.doc(self.base, **kw)  # noqa: E731
        self.expect(d(anchor=(n, hashes[-1])), "verified")
        rep = self.expect(d(anchor=(n - 1, hashes[-2])), "verified")
        need(rep.unanchored_tail == 1, "unanchored tail %d" % rep.unanchored_tail)
        self.expect(d(anchor=(n, "f" * 64)), "broken", {(n - 1, "anchor_head_mismatch")})
        self.expect(d(anchor=(n - 1, "f" * 64)), "broken", {(n - 2, "anchor_head_mismatch")})
        self.expect(d(anchor=(n + 1, hashes[-1])), "truncated", {(None, "anchor_exceeds_records")})
        for count in ("%d.0" % n, "1.1e1", "110e-1", "0.11E+2", "%d.000" % n):
            self.expect(d(raw_anchor='{"entry_count": %s, "head_hash": "%s"}'
                          % (count, hashes[-1])), "verified")
        for count in ("1e400", "1" + "0" * 50, "1e999999999999999999999"):
            self.expect(d(raw_anchor='{"entry_count": %s}' % count), "truncated",
                        {(None, "anchor_exceeds_records")})
        rep = self.expect(d(raw_anchor='{"entry_count": %d}' % n), "verified")
        need(rep.unanchored_tail == 0, "a head-less anchor reported a tail")
        self.expect(d(raw_anchor='{"entry_count": %d, "head_hash": null}' % (n + 9)), "truncated",
                    {(None, "anchor_exceeds_records")})
        for count in ("0", "-0", "0.0", "-0.0"):
            self.expect(d(raw_anchor='{"entry_count": %s, "head_hash": "x"}' % count), "verified")
        for raw in ('"zz"', '{"head_hash": "x"}', '{"entry_count": 2.5}', '{"entry_count": -1}',
                    '{"entry_count": "11"}', '{"entry_count": true}', '{"entry_count": null}',
                    '{"entry_count": 1e-999999999999999999999}', "[]", "11"):
            self.expect(d(raw_anchor=raw, info=("anchor_unreadable",)), "verified")
        self.expect(d(raw_anchor="null", info=("anchor_null",)), "verified")
        self.expect(d(raw_anchor='{"entry_count": %d, "head_hash": "%s", "generation": 7}'
                      % (n, hashes[-1])), "verified")
        return ("matching, lagging, mismatched, over-long and head-less anchors, entry_count in "
                "any notation (13.0, 1.1e1, 110e-1, 1e400), and absent, null and unreadable "
                "anchors give section 7's verdicts and codes")

    def gates(self):
        names = ["gate_decision_empty_arrays", "gate_decision_deny",
                 "gate_decision_client_disconnected", "gate_decision_shutdown_deny",
                 "gate_decision_connection_panicked", "gate_decision_timeout_deny",
                 "gate_decision_user_approve", "gate_decision_always_allow",
                 "gate_decision_restore"]
        gates = [loaded(self.s.by_name[name]) for name in names]
        gates.append(dict(gates[0], verdict="hold"))                 # (hold, allow)
        gates.append(dict(gates[1], decision="approve_later"))       # unrecognised
        recs = self.relink(self.base[:1] + [dict(g, seq=V.JInt(str(i + 1)))
                                            for i, g in enumerate(gates)])
        want = {"allow": 0, "not_allow": 0}
        for g in gates:
            if (g["verdict"], g["decision"]) in PAIRS:
                want[PAIRS[(g["verdict"], g["decision"])]] += 1
        rep = self.expect(self.doc(recs), "verified")
        got = rep.gate
        need(got["allow"] == want["allow"] and got["not_allow"] == want["not_allow"] and
             got["unrecognised_count"] == 1 and got["failed_verification"] == 0 and
             (got["unrecognised"][0]["verdict"], got["unrecognised"][0]["decision"]) ==
             ("hold", "approve_later"), "gate summary %s, expected %s" % (got, want))
        bad = list(recs)
        bad[1] = self.seal(dict(bad[1], prev_hash="e" * 64))         # an allow, link_break
        for i in range(2, len(bad)):                                 # the rest re-linked
            bad[i] = self.seal(dict(bad[i], prev_hash=bad[i - 1]["hash"]))
        rep = self.expect(self.doc(bad), "broken", {(1, "link_break")})
        need(rep.gate["allow"] == want["allow"] - 1 and rep.gate["failed_verification"] == 1,
             "a record failing rule 4 was counted: %s" % rep.gate)
        forged = list(recs)                                          # deny edited to approve
        k = 2
        need((forged[k]["verdict"], forged[k]["decision"]) == ("hold", "user_deny"),
             "record %d is not the deny" % k)
        forged[k] = self.seal(dict(forged[k], decision="user_approve"))
        rep = self.expect(self.doc(forged), "broken", {(k + 1, "link_break")})
        need(rep.gate["allow"] == want["allow"] and rep.gate["failed_verification"] == 2,
             "an edited, re-hashed record was counted as an allow: %s" % rep.gate)
        return ("%d allow and %d not-allow pairs counted by the pair, (hold, allow) an allow, "
                "an unrecognised pair reported raw; neither a record failing rule 4 nor one "
                "edited and re-hashed (link_break at the next index) counts as an allow"
                % (want["allow"], want["not_allow"]))

    def unusual_values(self):
        restore = loaded(self.s.by_name["gate_decision_restore"])
        inter = {k: v for k, v in self.base[2].items() if k != "hash"}
        k = self.n
        cases = [
            dict(restore, response_hash_upstream=None),               # no file could be read
            dict(inter, ai_response_truncated=True, gate_layer=V.JInt("-7"),
                 anomaly_score_canonical=V.JInt("-1")),
            dict(inter, user_message_sha256=inter["user_message_sha256"].upper(),
                 ai_response_sha256=inter["ai_response_sha256"][:63]),
            dict(inter, user_message="a" + "\U0001f512" * 262143,      # 3 bytes under the cap
                 user_message_truncated=True),
            dict(inter, user_message='quote " backslash \\ tab \t nul \x00 bidi ‮'),
        ]
        for case in cases:
            recs = self.relink(self.base + [dict(case, seq=V.JInt(str(k)))])
            self.expect(self.doc(recs), "verified")
        return ("a restore with no upstream digest, a truncated ai_response, negative scalars, "
                "uppercase and 63-character digests, content 3 bytes under the cap and strings "
                "that need JSON escapes all verify")

    def escaping(self):
        hostile = "\x1b[2J‮\nverdict         verified (exit 0)"
        recs = list(self.base)
        recs[7] = self.seal(dict(recs[7], decision=hostile))
        recs = self.relink(recs)
        rep = self.expect(self.doc(recs), "verified")
        need(rep.gate["unrecognised"][0]["decision"] == hostile, "raw decision not kept")
        recs[3] = dict(recs[3], **{hostile: hostile})
        self.expect(self.doc(recs), "broken", {(3, "unknown_member")})
        return ("control characters, bidi overrides and a forged verdict line in a token and a "
                "member name are escaped; --json keeps the raw value")

    def command_line(self):
        data = self.doc(self.base)
        for args in (["--help"], ["-h"], ["-", "--install-nonce", "zz"],
                     ["-", "--install-nonce", "00 " * 32], [os.path.join(HERE, "no-such-file")],
                     ["-", "--bogus"], ["-", "--anchor-table"], []):
            proc = cli(data, args)
            need(proc.returncode == V.EXIT_USAGE, "%s exited %d" % (args, proc.returncode))
        good = self.doc(self.base)
        for close, want in (((1,), V.EXIT_INTERNAL), ((2,), 0), ((1, 2), V.EXIT_INTERNAL)):
            proc = subprocess.run([sys.executable, "-I", VERIFIER, "-"], input=good,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  preexec_fn=lambda fds=close: [os.close(fd) for fd in fds])
            need(proc.returncode == want, "with fds %s closed: exit %d" % (close, proc.returncode))
        read, write = os.pipe()
        os.close(read)
        proc = subprocess.run([sys.executable, "-I", VERIFIER, "-"], input=good, stdout=write,
                              stderr=subprocess.DEVNULL)
        os.close(write)
        need(proc.returncode == V.EXIT_INTERNAL, "into a broken pipe: exit %d" % proc.returncode)
        return ("--help, bad arguments, the retired --anchor-table, a bad --install-nonce and an "
                "unreadable path exit 10; a report that cannot be written exits 11; a closed "
                "stderr changes nothing")

    def scale(self):
        import time
        big = "9" * 300000
        start = time.time()
        recs = self.edited(self.n - 1)
        recs[-1] = self.seal(dict(recs[-1], seq=V.JInt(big)))
        rep = self.expect(self.doc(recs, raw_anchor='{"entry_count": %s, "head_hash": "x"}'
                                   % ("7" * 300000)),
                          "truncated", {(self.n - 1, "seq_gap"),
                                        (None, "anchor_exceeds_records")})
        need(time.time() - start < 20, "took %.1f s" % (time.time() - start))
        need(all(len(f["detail"]) < 2000 for f in rep.findings), "an integer was printed whole")
        empties = ("[" + ", ".join(["{}"] * 50000) + "]").encode()
        data = b'{"voaf_version": "2.0", "genesis": "%s", "records": %s}' % (self.G.encode(),
                                                                           empties)
        rep = verify_both(data)
        need(rep.verdict == "broken" and len(rep.findings) == V.MAX_STORED_FINDINGS and
             rep.omitted + len(rep.findings) == sum(rep.counts.values()) == 300001 and
             rep.walked == 0, "50000 empty records: %s findings kept, %d omitted, counts %s"
             % (len(rep.findings), rep.omitted, rep.counts))
        return ("300000-digit integers are compared without conversion and printed cut; 50000 "
                "empty records (6 missing members each, none in the walk) keep %d findings and "
                "count all 300001 with anchor_absent" % V.MAX_STORED_FINDINGS)

def main():
    with open(VECTORS, "rb") as f:
        raw = f.read()
    try:
        vf = V.parse_json(raw)  # the vectors file itself has no repeated member name
    except V.Rejected as e:
        print("FAIL  vectors file does not parse: %s" % e)
        return 1
    suite = Suite(vf)
    passed = failed = 0

    def run(label, check, *args):
        nonlocal passed, failed
        try:
            ok, detail = True, check(*args)
        except Fail as e:
            ok, detail = False, str(e)
        except Exception as e:  # a crash is a failure, not a pass
            ok, detail = False, "error: %s: %s" % (type(e).__name__, e)
        passed, failed = passed + ok, failed + (not ok)
        print("%s  %s  %s" % ("PASS" if ok else "FAIL", label, detail), flush=True)

    for i, case in enumerate(vf["genesis"]["cases"]):
        run("genesis.cases[%d]" % i, suite.genesis_case, case)
    for i, v in enumerate(suite.vectors):
        run("vectors[%d] %s" % (i, v["name"]), suite.positive, v)
    run("chain", suite.chain_walk)
    for i, v in enumerate(vf["negative_vectors"]):
        run("negative_vectors[%d] %s" % (i, v["name"]), suite.negative, v)
    for i, v in enumerate(vf["negative_documents"]):
        run("negative_documents[%d] %s" % (i, v["name"]), suite.negative_doc, v)
    run("field_counts", suite.field_counts)
    vector_lines = (passed, failed)
    derived = Derived(suite)
    for name, where, check in derived.checks():
        run("derived: %s (%s)" % (name, where), check)
    print("vectors: %d passed, %d failed (%d positive, %d negative vectors, %d negative "
          "documents, plus genesis, chain and field_counts lines); derived checks: %d passed, "
          "%d failed" % (vector_lines + (len(suite.vectors), len(vf["negative_vectors"]),
                                         len(vf["negative_documents"]))
                         + (passed - vector_lines[0], failed - vector_lines[1])))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
