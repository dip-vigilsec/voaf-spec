//! Every vector in `spec/2.0/test-vectors.json`, run against the reference
//! verifier in `spec/2.0/reference-verifier.rs`.
//!
//! The counts are pinned. A vector added to the file without a check here, or a
//! check that stops reaching its vectors, fails on the count rather than passing
//! by not looking.

use serde_json::Value;
use voaf_reference_verifier as voaf;

const VECTORS: &str = include_str!("../../spec/2.0/test-vectors.json");

const POSITIVE: usize = 24;
const NEGATIVE: usize = 12;
const CHAIN: usize = 13;

fn file() -> Value {
    voaf::parse_document(VECTORS).expect("the vectors file parses, with no repeated member name")
}

fn positives(d: &Value) -> &Vec<Value> {
    d["vectors"].as_array().expect("vectors")
}

fn negatives(d: &Value) -> &Vec<Value> {
    d["negative_vectors"].as_array().expect("negative_vectors")
}

fn by_name<'a>(d: &'a Value, name: &str) -> &'a Value {
    positives(d)
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("no vector named {}", name))
}

/// A positive vector's record, with the vector-file `$repeat` directive expanded
/// (section 4.2.1). Only positive vectors go through here.
fn expanded(v: &Value) -> Value {
    voaf::expand_vector_record(&v["record"]).unwrap_or_else(|e| panic!("{}: {}", v["name"], e))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    voaf::hex(&Sha256::digest(bytes))
}

#[test]
fn every_positive_vector_reproduces_byte_for_byte() {
    let d = file();
    let vs = positives(&d);
    assert_eq!(vs.len(), POSITIVE, "positive vector count");
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let kind = v["event_kind"].as_str().unwrap();
        let p = voaf::preimage(kind, &expanded(v)).unwrap_or_else(|e| panic!("{}: {}", name, e));
        assert_eq!(p.len() as u64, v["preimage_len"].as_u64().unwrap(), "{}: preimage_len", name);
        assert_eq!(sha256_hex(&p), v["preimage_sha256"].as_str().unwrap(), "{}: preimage_sha256", name);
        assert_eq!(sha256_hex(&p), v["expected_hash"].as_str().unwrap(), "{}: expected_hash", name);
        match &v["preimage_hex"] {
            Value::String(h) => assert_eq!(&voaf::hex(&p), h, "{}: preimage_hex", name),
            Value::Null => assert!(p.len() > 4096, "{}: preimage_hex is null only above 4096 bytes", name),
            other => panic!("{}: preimage_hex is {}", name, other),
        }
    }
}

#[test]
fn every_positive_hash_is_distinct() {
    let d = file();
    let mut hashes: Vec<&str> = positives(&d).iter().map(|v| v["expected_hash"].as_str().unwrap()).collect();
    hashes.sort();
    hashes.dedup();
    assert_eq!(hashes.len(), POSITIVE, "two positive vectors share a hash");
}

/// Acceptance criterion 5, the retyped case: the same record with `rule_ids` as
/// an empty string hashes differently, to the value the file states.
#[test]
fn a_substituted_field_moves_the_hash() {
    let d = file();
    let mut seen = 0;
    for v in positives(&d).iter().filter(|v| v.get("substituted_field").is_some()) {
        let field = v["substituted_field"].as_str().unwrap();
        assert_eq!(field, "rule_ids", "only rule_ids substitutions are defined");
        assert_eq!(v["must_differ"], true);
        // Computed without the decoder, because the substitution is a type the
        // table forbids: the same preimage with field 15 encoded as an empty
        // string instead of an empty array.
        let p = voaf::preimage("gate_decision", &expanded(v)).unwrap();
        let empty_array = [0x04u8, 0, 0, 0, 0];
        let empty_string = [0x01u8, 0, 0, 0, 0];
        let at = p.windows(5).position(|w| w == empty_array).expect("rule_ids encodes as an empty array");
        let mut q = p.clone();
        q[at..at + 5].copy_from_slice(&empty_string);
        let h = sha256_hex(&q);
        assert_eq!(h, v["expected_hash_if_rule_ids_were_empty_string"].as_str().unwrap(), "{}", v["name"]);
        assert_ne!(h, v["expected_hash"].as_str().unwrap());
        seen += 1;
    }
    assert_eq!(seen, 1, "substitution vectors");
}

#[test]
fn every_genesis_case_reproduces() {
    let d = file();
    let cases = d["genesis"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let nonce = c["install_nonce_hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..nonce.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&nonce[i..i + 2], 16).unwrap())
            .collect();
        let arr: [u8; 32] = bytes.try_into().expect("a 32-byte nonce");
        assert_eq!(voaf::genesis(&arr), c["expected_genesis"].as_str().unwrap());
    }
}

#[test]
fn the_field_counts_match_section_2_2() {
    let d = file();
    let counts = d["field_counts"].as_object().unwrap();
    assert_eq!(counts.len(), 5);
    for (kind, n) in counts {
        assert_eq!(voaf::field_count(kind), n.as_i64(), "{}", kind);
    }
}

/// Section 7: walk exactly the `chain_member` vectors in `seq` order from the
/// genesis, advancing from the stored hash.
#[test]
fn the_chain_walks_from_the_genesis_to_the_head() {
    let d = file();
    let gi = d["chain"]["genesis_case_index"].as_u64().unwrap() as usize;
    let genesis = d["genesis"]["cases"][gi]["expected_genesis"].as_str().unwrap();
    let mut members: Vec<&Value> =
        positives(&d).iter().filter(|v| v["chain_member"] == true).collect();
    members.sort_by_key(|v| v["record"]["seq"].as_i64().unwrap());
    assert_eq!(members.len(), CHAIN, "chain length");
    assert_eq!(d["chain"]["entry_count"].as_u64().unwrap() as usize, CHAIN);
    assert_eq!(members[0]["event_kind"], "chain_upgrade", "record 0 is a chain_upgrade");
    let mut prev = genesis.to_string();
    for (i, v) in members.iter().enumerate() {
        let rec = expanded(v);
        assert_eq!(rec["seq"].as_u64().unwrap() as usize, i, "{}: seq", v["name"]);
        assert_eq!(rec["prev_hash"].as_str().unwrap(), prev, "{}: prev_hash", v["name"]);
        let h = voaf::record_hash(v["event_kind"].as_str().unwrap(), &rec).unwrap();
        assert_eq!(h, v["expected_hash"].as_str().unwrap());
        prev = h;
    }
    assert_eq!(prev, d["chain"]["head_hash"].as_str().unwrap(), "head");
}

/// The section 7 rule a decode error breaks, as the vectors file names it, so
/// that the file states an outcome any implementation can check rather than one
/// implementation's message text.
fn violation(e: &voaf::PreimageError) -> &'static str {
    use voaf::PreimageError::*;
    match e {
        UnknownMember(_) => "unknown_member",
        WrongType(_) => "wrong_type",
        NullField(_) => "null_field",
        NullElement(_) => "null_element",
        _ => "other",
    }
}

#[test]
fn every_negative_vector_fails_where_it_says() {
    let d = file();
    let ns = negatives(&d);
    assert_eq!(ns.len(), NEGATIVE, "negative vector count");
    for nv in ns {
        let name = nv["name"].as_str().unwrap();
        let want = nv.get("violation").and_then(Value::as_str);
        if let Some(text) = nv.get("record_json") {
            // The record as text, because what it tests is gone once parsed.
            assert_eq!(want, Some("duplicate_member"), "{}", name);
            let err = voaf::parse_document(text.as_str().unwrap()).expect_err(name);
            assert!(err.to_string().contains("is repeated in one object"), "{}: {}", name, err);
        } else if nv.get("record").is_some() {
            // A record exactly as a document carries it. Never expanded.
            let rec = &nv["record"];
            let kind = rec["event_kind"].as_str().unwrap();
            if want == Some("hash_mismatch") {
                let h = voaf::record_hash(kind, rec).unwrap_or_else(|e| panic!("{}: {}", name, e));
                assert_eq!(h, nv["expected_hash"].as_str().unwrap(), "{}", name);
                assert_ne!(h, nv["stored_hash"].as_str().unwrap(), "{}", name);
            } else {
                let err = voaf::preimage(kind, rec).expect_err(name);
                assert_eq!(Some(violation(&err)), want, "{}: {}", name, err);
            }
        } else {
            mutation(&d, nv);
        }
    }
}

/// The four revision 3 negative vectors, which describe a mutation of a basis
/// vector rather than carry a record.
fn mutation(d: &Value, nv: &Value) {
    let name = nv["name"].as_str().unwrap();
    let basis = by_name(d, nv["basis"].as_str().unwrap());
    let kind = basis["event_kind"].as_str().unwrap();
    let rec = expanded(basis);
    match name {
        // Field 1 is 0x01 u32be(8) "voaf-2.0"; field 2 is 0x02 u32be(2) "35".
        "neg_tag_mutated" | "neg_field_count_mutated" => {
            let mut p = voaf::preimage(kind, &rec).unwrap();
            if name == "neg_tag_mutated" {
                assert_eq!(&p[5..13], b"voaf-2.0");
                p[5..13].copy_from_slice(b"voaf-2.1");
            } else {
                assert_eq!(&p[13..20], &[0x02, 0, 0, 0, 2, b'3', b'5']);
                p[18..20].copy_from_slice(b"32");
            }
            let h = sha256_hex(&p);
            assert_eq!(h, nv["expected_hash"].as_str().unwrap(), "{}", name);
            assert_eq!(nv["must_differ_from"], basis["expected_hash"], "{}", name);
            assert_ne!(h, basis["expected_hash"].as_str().unwrap(), "{}", name);
        }
        "neg_content_over_limit" => {
            let mut r = rec.clone();
            r["user_message"] = Value::String("A".repeat(voaf::MAX_FIELD_BYTES + 1));
            let err = voaf::preimage(kind, &r).expect_err(name);
            assert_eq!(err.to_string(), "field user_message is 1048577 bytes, over the limit");
        }
        "neg_array_over_limit" => {
            let mut r = rec.clone();
            r["rule_ids"] = Value::Array(vec![Value::String("R".into()); voaf::MAX_ARRAY_ELEMS + 1]);
            let err = voaf::preimage(kind, &r).expect_err(name);
            assert_eq!(err.to_string(), "array rule_ids has 65537 elements, over the limit");
        }
        _ => panic!("{}: a negative vector with no record and no check here", name),
    }
}

/// The limits are inclusive (section 2.1): exactly 2^20 bytes encodes.
#[test]
fn a_field_at_the_limit_encodes() {
    let d = file();
    let v = by_name(&d, "interaction_minimal");
    let mut r = expanded(v);
    r["user_message"] = Value::String("A".repeat(voaf::MAX_FIELD_BYTES));
    voaf::preimage("interaction", &r).unwrap();
}

/// `parse_document` builds the same values serde_json does. It relies on
/// serde_json without `arbitrary_precision`, under which a number would reach the
/// visitor as a map.
#[test]
fn the_strict_parse_matches_serde_json() {
    let plain: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file(), plain);
    assert_eq!(voaf::parse_document("[1, -2, 1.5, null, true, \"x\", {}]").unwrap(), serde_json::json!([1, -2, 1.5, null, true, "x", {}]));
    assert!(voaf::parse_document("{\"a\": 1} {}").is_err(), "trailing content");
    assert!(voaf::parse_document("{\"a\": {\"b\": 1, \"b\": 1}}").is_err(), "a repeat at depth");
    assert!(voaf::parse_document("{\"a\": 1, \"\\u0061\": 1}").is_err(), "a repeat written with an escape");
}

/// The vectors-file loader clamps `count` before allocating, so a huge count
/// costs at most one field over the limit and fails in `preimage`, never an
/// allocation of the size asked for, and never a panic.
#[test]
fn a_huge_repeat_count_fails_at_the_limit_without_allocating_it() {
    let d = file();
    let base = by_name(&d, "interaction_minimal");
    for (ch, over) in [("A", voaf::MAX_FIELD_BYTES + 1), ("\u{65e5}", voaf::MAX_FIELD_BYTES + 2), ("\u{1f600}", voaf::MAX_FIELD_BYTES + 4)] {
        for count in [u64::MAX, 1 << 40, (voaf::MAX_FIELD_BYTES as u64) + 1] {
            let mut v = base.clone();
            v["record"]["user_message"] = serde_json::json!({"$repeat": {"char": ch, "count": count}});
            let rec = voaf::expand_vector_record(&v["record"]).unwrap();
            assert!(rec["user_message"].as_str().unwrap().len() <= over);
            let err = voaf::preimage("interaction", &rec).expect_err("over the limit");
            assert!(matches!(err, voaf::PreimageError::FieldTooLarge("user_message", _)), "{}", err);
        }
    }
}

/// Content is covered only where it is present and non-null.
#[test]
fn content_stripped_to_null_is_not_covered() {
    let d = file();
    let mut rec = expanded(by_name(&d, "interaction_minimal"));
    rec["user_message"] = Value::Null;
    rec["ai_response"] = Value::Null;
    assert!(!voaf::content_covered("interaction", &rec));
    rec["ai_response"] = Value::String(String::new());
    assert!(voaf::content_covered("interaction", &rec));
    assert!(!voaf::content_covered("lifecycle", &rec));
}
