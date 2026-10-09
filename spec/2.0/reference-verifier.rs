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
//! the 1.x relabel check, the document members and the anchor checks. It gains
//! them in a later pull request.
//!
//! Consequence, stated so nobody is surprised: a change to the preimage must be
//! made here as well, and the vector tests are what catch a miss.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::HashSet;

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
    MissingMember(&'static str),
    MalformedMember(&'static str),
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
            Self::UndeclaredFormat => write!(f, "the document declares no VOAF version section 7 recognises"),
            Self::MissingMember(m) => write!(f, "the document has no {} member", m),
            Self::MalformedMember(m) => write!(f, "the document's {} member is not of the shape section 7 gives it", m),
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

impl PreimageError {
    /// The section 7 code for this failure. `kind_mismatch` and `bad_repeat` are
    /// not section 7 codes: they come only from a caller that names a kind the
    /// record does not carry, and from the vectors-file loader, never from a
    /// document.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownKind(_) => "unknown_kind",
            Self::NotARecord => "wrong_type",
            Self::FormatMismatch(_) => "format_mismatch",
            Self::UndeclaredFormat => "unrecognised_format",
            Self::MissingMember(_) => "missing_member",
            Self::MalformedMember(_) => "malformed_member",
            Self::UnknownMember(_) => "unknown_member",
            Self::KindMismatch => "kind_mismatch",
            Self::MissingField(_) => "missing_field",
            Self::NullField(_) => "null_field",
            Self::NullElement(_) => "null_element",
            Self::WrongType(_) => "wrong_type",
            Self::FieldTooLarge(..) | Self::ArrayTooLarge(..) | Self::PreimageTooLarge(_) => "over_limit",
            Self::BadFeatureArity(_) => "feature_arity",
            Self::BadRepeat(_) => "bad_repeat",
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

/// A document that is not one JSON value (`invalid_json`), or one that repeats a
/// member name (`duplicate_member`).
pub struct ParseError {
    message: String,
    code: &'static str,
}

impl ParseError {
    /// The section 7 code: `duplicate_member` or `invalid_json`. A serde_json
    /// built in a way this parser refuses gives `unsupported_build`, which is not
    /// a section 7 code: no document parses under that build.
    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::fmt::Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
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
/// forbids, so this refuses to parse at all when serde_json is built that way.
pub fn parse_document(text: &str) -> Result<Value, ParseError> {
    if !serde_json::from_str::<Value>("-0").map(|v| v.is_f64()).unwrap_or(false) {
        return Err(ParseError {
            message: "serde_json is built with arbitrary_precision, which this parser does not support".into(),
            code: "unsupported_build",
        });
    }
    // Set when the parse stops at a repeated name, so the error carries its code
    // rather than leaving a caller to read it from serde_json's message.
    let repeated = Cell::new(false);
    let fail = |e: serde_json::Error| ParseError {
        message: e.to_string(),
        code: if repeated.get() { "duplicate_member" } else { "invalid_json" },
    };
    let mut de = serde_json::Deserializer::from_str(text);
    let v = Strict(&repeated).deserialize(&mut de).map_err(fail)?;
    de.end().map_err(fail)?;
    Ok(v)
}

/// Builds a `serde_json::Value` exactly as serde_json does, except that a
/// repeated member name is an error rather than a silent overwrite.
struct Strict<'a>(&'a Cell<bool>);

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
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
        while let Some(item) = seq.next_element_seed(Strict(self.0))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if members.contains_key(&name) {
                self.0.set(true);
                return Err(de::Error::custom(format!(
                    "member name \"{}\" is repeated in one object",
                    escaped(&name)
                )));
            }
            let value = map.next_value_seed(Strict(self.0))?;
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
    // that could carry other text. A NULL is a NULL, never a wrong type.
    match members.get("hash") {
        Some(Value::Null) => return Err(PreimageError::NullField("hash")),
        Some(h) if !h.is_string() => return Err(PreimageError::WrongType("hash")),
        _ => {}
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
        Some(Value::Null) => return Err(PreimageError::NullField("event_kind")),
        Some(_) => return Err(PreimageError::WrongType("event_kind")),
    };
    let stored = match members.get("hash") {
        None => return Err(PreimageError::MissingField("hash")),
        Some(Value::String(h)) => h.clone(),
        Some(Value::Null) => return Err(PreimageError::NullField("hash")),
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

/// Section 7: the major version a declared version names. A declared version is
/// digits and dots, runs of the ASCII digits 0 to 9 separated by single dots, and
/// its first run is the major version: `1` declares 1.x and `2` declares 2.x.
/// Anything else, a missing or non-string value included, names none.
fn declared_major(v: Option<&Value>) -> Option<u8> {
    let s = v?.as_str()?;
    if !s.split('.').all(|run| !run.is_empty() && run.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    match s.split('.').next() {
        Some("1") => Some(1),
        Some("2") => Some(2),
        _ => None,
    }
}

/// Section 7: which walk a document gets. A document that declares VOAF 1.x and
/// carries structure only 2.x defines (a `records` member, or an entry carrying
/// `event_kind`, `seq` or `timestamp_us`) is rejected, never walked link-only: the
/// declaration is a member no hash covers, and believing it would switch off
/// every content check. A 1.x document is either the 1.0 array of entries, each
/// declaring `voaf`, or an object declaring `voaf_version`; a 2.x document is an
/// object declaring `voaf_version`.
pub fn document_format(doc: &Value) -> R<Format> {
    const V2_ONLY: [&str; 3] = ["event_kind", "seq", "timestamp_us"];
    let (major, entries): (Option<u8>, Vec<&Value>) = match doc {
        // The array of entries is 1.0's shape, and an empty one is a 1.0 document
        // with no entries. It never gets the 2.x verdict `empty`.
        Value::Array(items) if items.is_empty() => return Ok(Format::V1),
        // An array of entries is 1.0's shape only, so every entry declares 1.x.
        Value::Array(items) => {
            let all_1x = items.iter().all(|e| declared_major(e.get("voaf")) == Some(1));
            (all_1x.then_some(1), items.iter().collect())
        }
        Value::Object(o) => {
            let mut entries = Vec::new();
            for list in ["records", "interactions"] {
                if let Some(Value::Array(items)) = o.get(list) {
                    entries.extend(items.iter());
                }
            }
            (declared_major(o.get("voaf_version")), entries)
        }
        _ => return Err(PreimageError::UndeclaredFormat),
    };
    match major {
        Some(1) => {
            if doc.get("records").is_some() {
                return Err(PreimageError::FormatMismatch("a records member".into()));
            }
            for e in entries {
                if let Some(m) = V2_ONLY.iter().find(|m| e.get(**m).is_some()) {
                    return Err(PreimageError::FormatMismatch(format!("an entry carrying {}", m)));
                }
            }
            Ok(Format::V1)
        }
        Some(2) => Ok(Format::V2),
        _ => Err(PreimageError::UndeclaredFormat),
    }
}

/// The members section 7 reads from a 2.x document, past `voaf_version`. Every
/// other top-level member is ignored.
struct Members<'a> {
    records: &'a [Value],
    genesis: &'a str,
    /// `entry_count`, and `head_hash` when it is a string.
    anchor: Option<(u64, Option<&'a str>)>,
}

/// Section 7: `records` an array and `genesis` a string, both required, and either
/// written as null counts as absent. The anchor's `entry_count` is read when it is
/// a JSON number whose value is a non-negative integer, in any notation, and its
/// `head_hash` when it is a string. An anchor whose `entry_count` cannot be read
/// is no anchor, as are null and Vigil 2.3.2's `{"unreadable": true}`, and
/// members of it other than those two, Vigil's `generation` among them, are
/// ignored.
fn members(doc: &Value) -> R<Members<'_>> {
    let records = match doc.get("records") {
        None | Some(Value::Null) => return Err(PreimageError::MissingMember("records")),
        Some(Value::Array(r)) => r.as_slice(),
        Some(_) => return Err(PreimageError::MalformedMember("records")),
    };
    let genesis = match doc.get("genesis") {
        None | Some(Value::Null) => return Err(PreimageError::MissingMember("genesis")),
        Some(Value::String(g)) => g.as_str(),
        Some(_) => return Err(PreimageError::MalformedMember("genesis")),
    };
    let anchor = doc.get("anchor").and_then(|a| {
        let n = a.get("entry_count")?;
        // 13, 13.0 and 1.3e1 are one count, and -0 is 0. serde_json reads an
        // integer of 2^64 or more as a float; it counts more records than any
        // document holds, so it exceeds the record count.
        let count = n.as_u64().or_else(|| {
            let f = n.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0)?;
            Some(if f >= 18_446_744_073_709_551_616.0 { u64::MAX } else { f as u64 })
        })?;
        Some((count, a.get("head_hash").and_then(Value::as_str)))
    });
    Ok(Members { records, genesis, anchor })
}

/// Section 7's verdict on a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every check passed, over at least one record.
    Verified,
    /// A record fails rule 1, 2, 3 or 4, a `seq` repeats, or the carried anchor's
    /// `head_hash` differs from the record it counts to.
    Broken,
    /// Record 0 is missing or is not what it must be, `seq` has a gap, or the
    /// carried anchor counts more records than the document holds.
    Truncated,
    /// Zero records, and no anchor that counts any.
    Empty,
    /// Not walked: the parse check, the format check or the member check failed.
    Rejected,
    /// Declares 1.x, or is the empty array of entries, and passed the format
    /// check. A 1.0 document is walked link-only, which this file does not do,
    /// and never gets a 2.x verdict.
    Version1,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Broken => "broken",
            Self::Truncated => "truncated",
            Self::Empty => "empty",
            Self::Rejected => "rejected",
            Self::Version1 => "1.x",
        }
    }
}

/// What the carried anchor says about the chain's tail. Section 7 makes a
/// verifier report the last two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// The anchor counts every record, and its `head_hash` matches.
    Anchored,
    /// The anchor's `head_hash` matches, over fewer records than the document
    /// holds: an unanchored tail of this many records.
    Unanchored(u64),
    /// No anchor, or one whose `entry_count` is 0 while records are present:
    /// truncation of the chain's tail cannot be detected from this document.
    Undetectable,
}

/// One failed check, by its section 7 code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The record's position in the document's `records` array, or None for a
    /// check on the whole document.
    pub record: Option<usize>,
    pub code: &'static str,
}

pub struct Report {
    pub verdict: Verdict,
    /// Every finding, whichever verdict wins.
    pub findings: Vec<Finding>,
    /// None when the document was not walked, when it has zero records and an
    /// anchor counting none, and when the anchor counts more records than the
    /// document holds, carries no `head_hash`, names a head that does not match,
    /// or counts to a record with no place in the walk or no stored hash to read.
    pub tail: Option<Tail>,
}

impl Report {
    /// Every code reported, each once, sorted.
    pub fn codes(&self) -> Vec<&'static str> {
        let mut codes: Vec<&'static str> = self.findings.iter().map(|f| f.code).collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }
}

/// The section 7 codes that make a walked chain `truncated`. Every other code a
/// walk reports makes it `broken`.
fn truncates(code: &str) -> bool {
    matches!(code, "root_missing" | "root_not_chain_upgrade" | "root_genesis_mismatch" | "seq_gap" | "anchor_exceeds_records")
}

fn rejected(code: &'static str) -> Report {
    Report { verdict: Verdict::Rejected, findings: vec![Finding { record: None, code }], tail: None }
}

/// Section 7 on a document's text: the parse check, the format check and the
/// document member check, which reject a document unwalked; rules 1 to 4 on every
/// record; and the chain checks, `seq`, record 0 and the carried anchor. A 1.x
/// document passes the format check and is not walked here. Records are walked in
/// ascending `seq` order, whatever order the array lists them in, and the chain
/// checks read a `seq` only where it is an integer and an `event_kind`,
/// `prev_hash` or `hash` only where it is a string. Where section 7 leaves it open
/// (the 2.1.1 errata), this file reports a record's first failure in the order
/// `preimage()` checks, makes no rule 3 check on a record that fails rule 1 or 2,
/// and makes rule 4 only where both values are strings.
pub fn verify_document(text: &str) -> Report {
    let doc = match parse_document(text) {
        Ok(doc) => doc,
        Err(e) => return rejected(e.code()),
    };
    match document_format(&doc) {
        Err(e) => return rejected(e.code()),
        Ok(Format::V1) => return Report { verdict: Verdict::Version1, findings: Vec::new(), tail: None },
        Ok(Format::V2) => {}
    }
    let m = match members(&doc) {
        Ok(m) => m,
        Err(e) => return rejected(e.code()),
    };
    let mut findings = Vec::new();
    let mut found = |record: usize, code: &'static str| findings.push(Finding { record: Some(record), code });

    // Rules 1 to 3, record by record.
    for (i, rec) in m.records.iter().enumerate() {
        match record(rec) {
            Ok((_, computed, stored)) if computed != stored => found(i, "hash_mismatch"),
            Ok(_) => {}
            Err(e) => found(i, e.code()),
        }
    }

    // The walk, grouped by `seq`: one group per value, in ascending order.
    let str_of = |i: usize, name: &str| m.records[i].get(name).and_then(Value::as_str);
    let mut walk: Vec<(i64, usize)> = m
        .records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.get("seq").and_then(Value::as_i64).map(|s| (s, i)))
        .collect();
    walk.sort_unstable();
    let mut groups: Vec<(i64, Vec<usize>)> = Vec::new();
    for &(s, i) in &walk {
        match groups.last_mut() {
            Some((gs, g)) if *gs == s => g.push(i),
            _ => groups.push((s, vec![i])),
        }
    }
    let stored_hashes = |g: &[usize]| -> HashSet<&str> { g.iter().filter_map(|&i| str_of(i, "hash")).collect() };

    for (_, g) in &groups {
        for &i in &g[1..] {
            found(i, "duplicate_seq");
        }
    }
    if let Some((first, g)) = groups.first() {
        if *first != 0 {
            found(g[0], "root_missing");
        } else {
            for &i in g {
                if str_of(i, "event_kind").is_some_and(|k| k != "chain_upgrade") {
                    found(i, "root_not_chain_upgrade");
                }
                if str_of(i, "prev_hash").is_some_and(|p| p != m.genesis) {
                    found(i, "root_genesis_mismatch");
                }
            }
        }
    }
    // Rule 4 links each record to the record before it in the walk, the one with
    // the next lower `seq`; where several share that `seq`, to any of them.
    for pair in groups.windows(2) {
        let ((before, prev), (s, g)) = (&pair[0], &pair[1]);
        if before.checked_add(1) != Some(*s) {
            found(g[0], "seq_gap");
        }
        let stored = stored_hashes(prev);
        for &i in g {
            if let Some(p) = str_of(i, "prev_hash") {
                if !stored.is_empty() && !stored.contains(p) {
                    found(i, "link_break");
                }
            }
        }
    }

    // The carried anchor. The record count is the length of `records`.
    let n = m.records.len() as u64;
    let tail = match m.anchor {
        None => Some(Tail::Undetectable),
        Some((count, _)) if count > n => {
            findings.push(Finding { record: None, code: "anchor_exceeds_records" });
            None
        }
        Some((0, _)) if n == 0 => None,
        Some((0, _)) => Some(Tail::Undetectable),
        Some((_, None)) => None,
        Some((count, Some(head))) => {
            // The record at position count - 1 of the walk, counting from 0; where
            // several records share its `seq`, any of them.
            match walk.get((count - 1) as usize) {
                None => None,
                Some(&(s, at)) => {
                    let g = &groups.iter().find(|(gs, _)| *gs == s).expect("every walked seq has a group").1;
                    let stored = stored_hashes(g);
                    if stored.is_empty() {
                        None
                    } else if !stored.contains(head) {
                        findings.push(Finding { record: Some(at), code: "anchor_head_mismatch" });
                        None
                    } else if count < n {
                        Some(Tail::Unanchored(n - count))
                    } else {
                        Some(Tail::Anchored)
                    }
                }
            }
        }
    };

    let verdict = if findings.iter().any(|f| !truncates(f.code)) {
        Verdict::Broken
    } else if !findings.is_empty() {
        Verdict::Truncated
    } else if n == 0 {
        Verdict::Empty
    } else {
        Verdict::Verified
    };
    Report { verdict, findings, tail }
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
