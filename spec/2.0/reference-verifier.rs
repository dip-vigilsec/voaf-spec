//! The VOAF 2.0 reference verifier: the preimage of `spec/2.0/preimage.md`, and
//! the section 7 checks on a document and its records.
//!
//! Deliberately NOT shared with the writer.
//!
//! This file exists so a third party can verify a document without Vigil
//! installed, and so that agreement between the writer and the verifier is
//! evidence. If both called one function, agreement would prove only that the
//! function is self-consistent. The test vectors in `spec/2.0/test-vectors.json`
//! are the contract between the two implementations, and
//! `verifier/tests/vectors.rs` holds this one to them.
//!
//! It is independent of the writer, Vigil's `chain::preimage`, and of nothing
//! else: it began as the preimage module of Vigil's vigil-verify
//! (`vigil-verify/src/voaf.rs`), so agreement between the two is one lineage
//! agreeing with itself. vigil-verify does not yet make the 2.1.0 checks this
//! file makes: the parse check, the closed member set, rule 1 for every field,
//! and the 1.x relabel check. It gains them in a later pull request.
//!
//! Consequence, stated so nobody is surprised: a change to the preimage must be
//! made here as well, and the vector tests are what catch a miss.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const TAG: &str = "voaf-2.0";

const M_NULL: u8 = 0x00;
const M_STR: u8 = 0x01;
const M_INT: u8 = 0x02;
const M_BOOL: u8 = 0x03;
const M_ARR: u8 = 0x04;

pub const MAX_FIELD_BYTES: usize = 1 << 20;
pub const MAX_ARRAY_ELEMS: usize = 1 << 16;
pub const MAX_PREIMAGE_BYTES: usize = 1 << 24;

/// One field of a record, in spec order, with its declared type.
#[derive(Clone, Copy, PartialEq)]
pub enum Ty {
    Str,
    Int,
    Bool,
    ArrStr,
    ArrInt,
}

/// The Nullable column of the section 4 tables.
#[derive(Clone, Copy, PartialEq)]
pub enum Nullable {
    Yes,
    No,
}

/// Envelope fields 3, 4, 6 and 7, as a record carries them. None is nullable.
/// Fields 1 and 2 are constants, and field 5 is the kind.
pub const ENVELOPE: [&str; 4] = ["seq", "prev_hash", "id", "timestamp_us"];

/// The two members of a document record that are not decoded as fields:
/// `event_kind`, which selects the table and must name the kind being decoded,
/// and `hash`, the stored hash section 7 rule 3 compares against.
pub const RECORD_MEMBERS: [&str; 2] = ["event_kind", "hash"];

/// Spec section 4. Field order, type and nullability per event kind, body only;
/// the envelope is fields 1 to 7 and is emitted by `preimage`.
pub fn schema(kind: &str) -> Option<&'static [(&'static str, Ty, Nullable)]> {
    use Nullable::*;
    use Ty::*;
    Some(match kind {
        "interaction" => &[
            ("provider", Str, No),
            ("model", Str, Yes),
            ("interaction_type", Str, No),
            ("conversation_ref", Str, Yes),
            ("client_ref", Str, Yes),
            ("user_message", Str, Yes),
            ("user_message_sha256", Str, Yes),
            ("user_message_length", Int, Yes),
            ("user_message_truncated", Bool, No),
            ("ai_response", Str, Yes),
            ("ai_response_sha256", Str, Yes),
            ("ai_response_length", Int, Yes),
            ("ai_response_truncated", Bool, No),
            ("action", Str, No),
            ("scope", Str, No),
            ("features_canonical", ArrInt, No),
            ("risk_tier", Str, No),
            ("anomaly_score_canonical", Int, Yes),
            ("is_anomaly", Bool, No),
            ("policy_action", Str, No),
            ("matched_policy", Str, Yes),
            ("blocked", Bool, Yes),
            ("block_reason", Str, Yes),
            ("policy_id", Str, Yes),
            ("gate_layer", Int, Yes),
            ("tap_certificate_id", Str, Yes),
            ("scope_violation", Bool, No),
            ("execution_gate_id", Str, Yes),
        ],
        "gate_decision" => &[
            ("gate_id", Str, No),
            ("interaction_id", Str, Yes),
            ("provider", Str, No),
            ("protocol", Str, No),
            ("tool_call_id", Str, Yes),
            ("tool_name", Str, Yes),
            ("class", Str, No),
            ("rule_ids", ArrStr, No),
            ("verdict", Str, No),
            ("decision", Str, No),
            ("held_ms", Int, No),
            ("snapshot_ids", ArrStr, No),
            ("response_hash_upstream", Str, Yes),
            ("response_hash_delivered", Str, Yes),
            ("actor", Str, No),
            ("policy_version", Str, No),
        ],
        "chain_upgrade" => &[
            ("predecessor_format_version", Str, Yes),
            ("predecessor_document_sha256", Str, Yes),
            ("predecessor_record_count", Int, Yes),
            ("predecessor_head_hash", Str, Yes),
        ],
        "chain_truncation" => &[
            ("anchor_entry_count", Int, No),
            ("anchor_head_hash", Str, No),
            ("observed_entry_count", Int, No),
            ("observed_head_hash", Str, No),
        ],
        "lifecycle" => &[("event", Str, No), ("app_version", Str, No), ("reason", Str, Yes)],
        _ => return None,
    })
}

/// Spec 2.2. Normative per kind, taken from the table and never recomputed.
pub fn field_count(kind: &str) -> Option<i64> {
    schema(kind).map(|body| 7 + body.len() as i64)
}

pub enum PreimageError {
    UnknownKind(String),
    NotARecord,
    FormatMismatch(String),
    UndeclaredFormat,
    UnknownMember(String),
    KindMismatch,
    MissingField(&'static str),
    NullField(&'static str),
    NullElement(&'static str),
    WrongType(&'static str),
    FieldTooLarge(&'static str, usize),
    ArrayTooLarge(&'static str, usize),
    PreimageTooLarge(usize),
    BadFeatureArity(usize),
    BadRepeat(String),
}

impl std::fmt::Display for PreimageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKind(k) => write!(f, "unknown event_kind \"{}\"", escaped(k)),
            Self::NotARecord => write!(f, "the record is not a JSON object"),
            Self::FormatMismatch(why) => write!(f, "the document declares VOAF 1.x and carries {}", why),
            Self::UndeclaredFormat => write!(f, "the document declares no VOAF version"),
            Self::UnknownMember(m) => {
                write!(f, "member \"{}\" is not a field of this kind", escaped(m))
            }
            Self::KindMismatch => write!(f, "member event_kind does not name the kind being decoded"),
            Self::MissingField(n) => write!(f, "missing field {}", n),
            Self::NullField(n) => write!(f, "field {} is null, and it is not nullable", n),
            Self::NullElement(n) => write!(f, "an element of {} is null, and array elements never are", n),
            Self::WrongType(n) => write!(f, "field {} has the wrong type", n),
            Self::FieldTooLarge(n, l) => write!(f, "field {} is {} bytes, over the limit", n, l),
            Self::ArrayTooLarge(n, l) => write!(f, "array {} has {} elements, over the limit", n, l),
            Self::PreimageTooLarge(l) => write!(f, "preimage is {} bytes, over the limit", l),
            Self::BadFeatureArity(l) => {
                write!(f, "features_canonical has {} elements, expected 27", l)
            }
            Self::BadRepeat(n) => write!(f, "vector field \"{}\" is not a well-formed $repeat directive", escaped(n)),
        }
    }
}

/// Debug is what `unwrap`, `expect` and a `main` that returns this error print,
/// so it writes the same escaped text as Display rather than a derived form that
/// would show a document string raw.
impl std::fmt::Debug for PreimageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// A document string in a message: an unknown kind, a member name. Printable
/// ASCII as itself, the backslash and the quote escaped, everything else as a
/// `\u{..}` escape: never the short forms `\n`, `\r` or `\t`, which a shell's
/// `echo` turns back into the characters they name. A caller that prints a message
/// can then be handed neither a line break, a terminal control nor a lookalike of
/// a real name.
fn escaped(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ' '..='~' => out.push(c),
            _ => out.push_str(&c.escape_unicode().to_string()),
        }
    }
    out
}

/// A document that is not one JSON value, or one that repeats a member name.
pub struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parse a document's text: the section 7 parse check. An object that repeats a
/// member name, at any depth, does not decode (RFC 7493 section 2.3).
/// A parser that keeps one copy of a repeated name has discarded the other before
/// anything can look at it, so the check has to be made while parsing; a
/// `serde_json::Value` cannot show it. Every `Value` given to `preimage` should
/// come from here.
///
/// Build this file with serde_json's default number handling. Under its
/// `arbitrary_precision` feature `-0` reads as the integer 0, which section 2
/// forbids, and a number outside i64 and u64 reaches the visitor as a map, so
/// this refuses to parse at all when serde_json is built that way.
pub fn parse_document(text: &str) -> Result<Value, ParseError> {
    if !serde_json::from_str::<Value>("-0").map(|v| v.is_f64()).unwrap_or(false) {
        return Err(ParseError(
            "serde_json is built with arbitrary_precision, which this parser does not support".into(),
        ));
    }
    let mut de = serde_json::Deserializer::from_str(text);
    let v = Strict.deserialize(&mut de).map_err(|e| ParseError(e.to_string()))?;
    de.end().map_err(|e| ParseError(e.to_string()))?;
    Ok(v)
}

/// Builds a `serde_json::Value` exactly as serde_json does, except that a
/// repeated member name is an error rather than a silent overwrite.
struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }
    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Value, E> {
        Ok(n.into())
    }
    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Value, E> {
        Ok(n.into())
    }
    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_owned()))
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if name.starts_with("$serde_json::private::") {
                return Err(de::Error::custom(
                    "serde_json is built with a number or raw-value feature this parser does not support",
                ));
            }
            if members.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "member name \"{}\" is repeated in one object",
                    escaped(&name)
                )));
            }
            let value = map.next_value_seed(Strict)?;
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}

type R<T> = Result<T, PreimageError>;

struct Buf {
    out: Vec<u8>,
}

impl Buf {
    fn put(&mut self, marker: u8, payload: &[u8], name: &'static str) -> R<()> {
        if payload.len() > MAX_FIELD_BYTES {
            return Err(PreimageError::FieldTooLarge(name, payload.len()));
        }
        // Bound as the buffer grows, not once it is built: the per-field and
        // per-array limits alone permit 2^16 elements of 2^20 bytes.
        let projected = self.out.len() + 1 + 4 + payload.len();
        if projected > MAX_PREIMAGE_BYTES {
            return Err(PreimageError::PreimageTooLarge(projected));
        }
        self.out.push(marker);
        self.out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        self.out.extend_from_slice(payload);
        Ok(())
    }

    fn null(&mut self) {
        self.out.push(M_NULL);
    }

    fn str_field(&mut self, s: &str, name: &'static str) -> R<()> {
        self.put(M_STR, s.as_bytes(), name)
    }

    fn int_field(&mut self, n: i64, name: &'static str) -> R<()> {
        self.put(M_INT, n.to_string().as_bytes(), name)
    }

    fn bool_field(&mut self, b: bool, name: &'static str) -> R<()> {
        self.put(M_BOOL, if b { b"1" } else { b"0" }, name)
    }
}

// The decoders below take a value already known not to be NULL. An object or an
// array where the table declares a scalar is the wrong type: nothing is
// expanded or unwrapped (section 4.2.1).

fn as_str<'a>(v: &'a Value, name: &'static str) -> R<&'a str> {
    v.as_str().ok_or(PreimageError::WrongType(name))
}

fn as_int(v: &Value, name: &'static str) -> R<i64> {
    v.as_i64().ok_or(PreimageError::WrongType(name))
}

fn as_bool(v: &Value, name: &'static str) -> R<bool> {
    v.as_bool().ok_or(PreimageError::WrongType(name))
}

/// Build the preimage for one record.
///
/// `rec` carries the envelope fields (`seq`, `prev_hash`, `id`, `timestamp_us`)
/// and the body fields for its kind, flat, and optionally `event_kind` and `hash`;
/// nothing else. A positive vector's record carries `event_kind` and no `hash`;
/// a document's record carries both, and `record()` requires them. The member set is checked
/// first; the type, nullability and limit checks run field by field in section 4
/// order, so a record with several defects reports the first, and no preimage is
/// returned unless every check passes.
pub fn preimage(kind: &str, rec: &Value) -> R<Vec<u8>> {
    let body = schema(kind).ok_or_else(|| PreimageError::UnknownKind(kind.to_string()))?;
    let count = field_count(kind).unwrap();
    let members = rec.as_object().ok_or(PreimageError::NotARecord)?;

    // A record carries exactly the envelope, `event_kind`, `hash` and its kind's
    // section 4 fields. Section 2.2 makes any other field a new tag, so no
    // voaf-2.0 record carries one, and a member no preimage reads is text no hash
    // covers.
    for name in members.keys() {
        let known = ENVELOPE.contains(&name.as_str())
            || RECORD_MEMBERS.contains(&name.as_str())
            || body.iter().any(|(n, _, _)| n == name);
        if !known {
            return Err(PreimageError::UnknownMember(name.clone()));
        }
    }
    // `event_kind` is field 5. A record that carries it names the kind being
    // decoded, or the member would be text the hash does not cover.
    if let Some(k) = members.get("event_kind") {
        if k.as_str() != Some(kind) {
            return Err(PreimageError::KindMismatch);
        }
    }
    // `hash` is the stored hash rule 3 compares against: a string, never anything
    // that could carry other text.
    if let Some(h) = members.get("hash") {
        if !h.is_string() {
            return Err(PreimageError::WrongType("hash"));
        }
    }

    let get = |n: &'static str| -> R<&Value> {
        let v = members.get(n).ok_or(PreimageError::MissingField(n))?;
        Ok(v)
    };
    let envelope = |n: &'static str| -> R<&Value> {
        let v = get(n)?;
        if v.is_null() {
            return Err(PreimageError::NullField(n));
        }
        Ok(v)
    };

    let mut b = Buf { out: Vec::with_capacity(512) };
    b.str_field(TAG, "tag")?;
    b.int_field(count, "field_count")?;
    b.int_field(as_int(envelope("seq")?, "seq")?, "seq")?;
    b.str_field(as_str(envelope("prev_hash")?, "prev_hash")?, "prev_hash")?;
    b.str_field(kind, "event_kind")?;
    b.str_field(as_str(envelope("id")?, "id")?, "id")?;
    b.int_field(as_int(envelope("timestamp_us")?, "timestamp_us")?, "timestamp_us")?;

    for (name, ty, nullable) in body {
        let v = get(name)?;
        if v.is_null() {
            // Section 7 rule 1, from the Nullable column of the section 4 table.
            if *nullable == Nullable::No {
                return Err(PreimageError::NullField(name));
            }
            b.null();
            continue;
        }
        match ty {
            Ty::Str => b.str_field(as_str(v, name)?, name)?,
            Ty::Int => b.int_field(as_int(v, name)?, name)?,
            Ty::Bool => b.bool_field(as_bool(v, name)?, name)?,
            Ty::ArrStr | Ty::ArrInt => {
                let items = v.as_array().ok_or(PreimageError::WrongType(name))?;
                if items.len() > MAX_ARRAY_ELEMS {
                    return Err(PreimageError::ArrayTooLarge(name, items.len()));
                }
                if *name == "features_canonical" && items.len() != 27 {
                    return Err(PreimageError::BadFeatureArity(items.len()));
                }
                b.out.push(M_ARR);
                b.out.extend_from_slice(&(items.len() as u32).to_be_bytes());
                for it in items {
                    // Section 2: array elements are never NULL.
                    if it.is_null() {
                        return Err(PreimageError::NullElement(name));
                    }
                    if *ty == Ty::ArrStr {
                        b.str_field(as_str(it, name)?, name)?;
                    } else {
                        b.int_field(as_int(it, name)?, name)?;
                    }
                }
            }
        }
    }

    if b.out.len() > MAX_PREIMAGE_BYTES {
        return Err(PreimageError::PreimageTooLarge(b.out.len()));
    }
    Ok(b.out)
}

pub fn record_hash(kind: &str, rec: &Value) -> R<String> {
    Ok(hex(&Sha256::digest(preimage(kind, rec)?)))
}

/// A record as a document carries it (section 7 rule 1): `event_kind` and `hash`
/// are present strings, and every other check `preimage` makes passes. Returns
/// the kind, the recomputed hash and the stored hash, for rule 3 to compare.
pub fn record(rec: &Value) -> R<(String, String, String)> {
    let members = rec.as_object().ok_or(PreimageError::NotARecord)?;
    let kind = match members.get("event_kind") {
        None => return Err(PreimageError::MissingField("event_kind")),
        Some(Value::String(k)) => k.clone(),
        Some(_) => return Err(PreimageError::WrongType("event_kind")),
    };
    let stored = match members.get("hash") {
        None => return Err(PreimageError::MissingField("hash")),
        Some(Value::String(h)) => h.clone(),
        Some(_) => return Err(PreimageError::WrongType("hash")),
    };
    let computed = record_hash(&kind, rec)?;
    Ok((kind, computed, stored))
}

/// The declared format of a document, once section 7's relabel check has passed.
#[derive(Debug, PartialEq)]
pub enum Format {
    V1,
    V2,
}

/// Section 7: which walk a document gets. A document that declares VOAF 1.x and
/// carries structure only 2.x defines (a `records` member, or an entry carrying
/// `event_kind`, `seq` or `timestamp_us`) is rejected, never walked link-only: the
/// declaration is a member no hash covers, and believing it would switch off
/// every content check. A 1.x document is either the 1.0 array of entries, each
/// declaring `voaf`, or an object declaring `voaf_version`.
pub fn document_format(doc: &Value) -> R<Format> {
    const V2_ONLY: [&str; 3] = ["event_kind", "seq", "timestamp_us"];
    let (declared, entries): (Option<&str>, Vec<&Value>) = match doc {
        // The array of entries is 1.0's shape, and an empty one is an empty 1.0
        // document: section 7 reports it `empty`.
        Value::Array(items) if items.is_empty() => return Ok(Format::V1),
        Value::Array(items) => (
            items.first().and_then(|e| e.get("voaf")).and_then(Value::as_str),
            items.iter().collect(),
        ),
        Value::Object(o) => {
            let declared = o.get("voaf_version").or_else(|| o.get("voaf")).and_then(Value::as_str);
            let mut entries = Vec::new();
            for list in ["records", "interactions"] {
                if let Some(Value::Array(items)) = o.get(list) {
                    entries.extend(items.iter());
                }
            }
            (declared, entries)
        }
        _ => return Err(PreimageError::UndeclaredFormat),
    };
    let declared = declared.ok_or(PreimageError::UndeclaredFormat)?;
    if declared.starts_with('1') {
        if doc.get("records").is_some() {
            return Err(PreimageError::FormatMismatch("a records member".into()));
        }
        for e in entries {
            if let Some(m) = V2_ONLY.iter().find(|m| e.get(**m).is_some()) {
                return Err(PreimageError::FormatMismatch(format!("an entry carrying {}", m)));
            }
        }
        return Ok(Format::V1);
    }
    Ok(Format::V2)
}

/// The vectors file only (spec section 4.2.1). A vector may abbreviate a long
/// string field as `{"$repeat": {"char": c, "count": n}}`. This returns a positive
/// vector's `record`, of the given kind, with each such field expanded, ready for
/// `preimage`. A document is
/// never passed through here, which is why `preimage` expands nothing: in a
/// document the directive is an object in a scalar field, and it does not decode.
pub fn expand_vector_record(kind: &str, record: &Value) -> R<Value> {
    let body = schema(kind).ok_or_else(|| PreimageError::UnknownKind(kind.to_string()))?;
    let fields = record.as_object().ok_or(PreimageError::NotARecord)?;
    // Names first: only a declared field may carry the directive, and nothing is
    // expanded for a record that `preimage` would reject anyway.
    for name in fields.keys() {
        let known = ENVELOPE.contains(&name.as_str())
            || RECORD_MEMBERS.contains(&name.as_str())
            || body.iter().any(|(n, _, _)| n == name);
        if !known {
            return Err(PreimageError::UnknownMember(name.clone()));
        }
    }
    let mut out = serde_json::Map::new();
    for (name, v) in fields {
        out.insert(name.clone(), expand_repeat(name, v)?);
    }
    Ok(Value::Object(out))
}

/// One vector field: unchanged unless it is an object, which must be the
/// directive and nothing else. `char` is one Unicode scalar value and `count` a
/// non-negative integer, and neither object has any other member.
fn expand_repeat(name: &str, v: &Value) -> R<Value> {
    let Value::Object(outer) = v else { return Ok(v.clone()) };
    let bad = || PreimageError::BadRepeat(name.to_string());
    let inner = match (outer.len(), outer.get("$repeat")) {
        (1, Some(Value::Object(inner))) if inner.len() == 2 => inner,
        _ => return Err(bad()),
    };
    let c = inner.get("char").and_then(Value::as_str).ok_or_else(bad)?;
    if c.chars().count() != 1 {
        return Err(bad());
    }
    let n = inner.get("count").and_then(Value::as_u64).ok_or_else(bad)?;
    // Clamp before allocating, as Vigil's vigil-verify has since 204a776. The
    // count is a number in a file, and expanding it faithfully lets a few bytes
    // of JSON ask for gigabytes, or overflow and panic, before the per-field limit
    // is ever checked. One character over the limit is enough for `preimage` to
    // reject the field, and costs at most 1 MB to build.
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    let per = c.len();
    if n.saturating_mul(per) > MAX_FIELD_BYTES {
        return Ok(Value::String(c.repeat(MAX_FIELD_BYTES / per + 1)));
    }
    Ok(Value::String(c.repeat(n)))
}

/// Part of the format surface, exercised by the vector tests. The binary does
/// not derive the genesis: a document carries it, because a verifier that had to
/// reconstruct it would need the install's keychain nonce and could then only
/// ever verify its own machine's documents.
#[allow(dead_code)]
pub fn genesis(nonce: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"vigil-genesis");
    h.update(nonce);
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Whether this record's own content is covered by its hash. Meaningful only for
/// a record that has decoded.
///
/// Only `interaction` records carry content. A v1 record covers none of it,
/// which is the whole reason for 2.0, and the verifier says so per record.
pub fn content_covered(kind: &str, rec: &Value) -> bool {
    // Present and a string, so not NULL, as Vigil's vigil-verify has required
    // present and non-null since dfba3ad.
    // `Value::get` returns Some(Value::Null) for a member that is present and
    // null, so an `is_some()` here counted a record whose content had been
    // stripped to nulls as content covered by its hash. Such a record still
    // verifies, correctly, because it is internally consistent; this answer was
    // the only thing that would have said otherwise.
    kind == "interaction"
        && ["user_message", "ai_response"]
            .iter()
            .any(|k| rec.get(*k).is_some_and(Value::is_string))
}
