//! The VOAF 2.0 preimage, implemented from `docs/specs/voaf-2.0-preimage.md`.
//!
//! Deliberately NOT shared with the writer.
//!
//! This crate exists so a third party can verify a document without Vigil
//! installed, and so that agreement between the writer and the verifier is
//! evidence. If both called one function, agreement would prove only that the
//! function is self-consistent. The checked-in test vectors are the contract
//! between the two implementations, and `tests/vectors.rs` holds this one to
//! them.
//!
//! Consequence, stated so nobody is surprised: a change to the preimage must be
//! made here as well, and the vector tests are what catch a miss.

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

/// Spec section 4. Field order and type per event kind, body only; the envelope
/// is fields 1 to 7 and is emitted by `preimage`.
pub fn schema(kind: &str) -> Option<&'static [(&'static str, Ty)]> {
    use Ty::*;
    Some(match kind {
        "interaction" => &[
            ("provider", Str),
            ("model", Str),
            ("interaction_type", Str),
            ("conversation_ref", Str),
            ("client_ref", Str),
            ("user_message", Str),
            ("user_message_sha256", Str),
            ("user_message_length", Int),
            ("user_message_truncated", Bool),
            ("ai_response", Str),
            ("ai_response_sha256", Str),
            ("ai_response_length", Int),
            ("ai_response_truncated", Bool),
            ("action", Str),
            ("scope", Str),
            ("features_canonical", ArrInt),
            ("risk_tier", Str),
            ("anomaly_score_canonical", Int),
            ("is_anomaly", Bool),
            ("policy_action", Str),
            ("matched_policy", Str),
            ("blocked", Bool),
            ("block_reason", Str),
            ("policy_id", Str),
            ("gate_layer", Int),
            ("tap_certificate_id", Str),
            ("scope_violation", Bool),
            ("execution_gate_id", Str),
        ],
        "gate_decision" => &[
            ("gate_id", Str),
            ("interaction_id", Str),
            ("provider", Str),
            ("protocol", Str),
            ("tool_call_id", Str),
            ("tool_name", Str),
            ("class", Str),
            ("rule_ids", ArrStr),
            ("verdict", Str),
            ("decision", Str),
            ("held_ms", Int),
            ("snapshot_ids", ArrStr),
            ("response_hash_upstream", Str),
            ("response_hash_delivered", Str),
            ("actor", Str),
            ("policy_version", Str),
        ],
        "chain_upgrade" => &[
            ("predecessor_format_version", Str),
            ("predecessor_document_sha256", Str),
            ("predecessor_record_count", Int),
            ("predecessor_head_hash", Str),
        ],
        "chain_truncation" => &[
            ("anchor_entry_count", Int),
            ("anchor_head_hash", Str),
            ("observed_entry_count", Int),
            ("observed_head_hash", Str),
        ],
        "lifecycle" => &[("event", Str), ("app_version", Str), ("reason", Str)],
        _ => return None,
    })
}

/// Spec 2.2. Normative per kind, taken from the table and never recomputed.
pub fn field_count(kind: &str) -> Option<i64> {
    schema(kind).map(|body| 7 + body.len() as i64)
}

#[derive(Debug)]
pub enum PreimageError {
    UnknownKind(String),
    MissingField(&'static str),
    NullField(&'static str),
    WrongType(&'static str),
    FieldTooLarge(&'static str, usize),
    ArrayTooLarge(&'static str, usize),
    PreimageTooLarge(usize),
    BadFeatureArity(usize),
}

impl std::fmt::Display for PreimageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The kind is the one document string a message carries. Escaped
            // in full: everything outside printable ASCII, the backslash and
            // the quotes, so a caller that prints this cannot be handed a line
            // break, a terminal control or a lookalike of a real kind.
            Self::UnknownKind(k) => write!(f, "unknown event_kind \"{}\"", k.escape_default()),
            Self::MissingField(n) => write!(f, "missing field {}", n),
            Self::NullField(n) => write!(f, "field {} is null, and it is not nullable", n),
            Self::WrongType(n) => write!(f, "field {} has the wrong type", n),
            Self::FieldTooLarge(n, l) => write!(f, "field {} is {} bytes, over the limit", n, l),
            Self::ArrayTooLarge(n, l) => write!(f, "array {} has {} elements, over the limit", n, l),
            Self::PreimageTooLarge(l) => write!(f, "preimage is {} bytes, over the limit", l),
            Self::BadFeatureArity(l) => {
                write!(f, "features_canonical has {} elements, expected 27", l)
            }
        }
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

    fn str_field(&mut self, v: Option<&str>, name: &'static str) -> R<()> {
        match v {
            None => {
                self.null();
                Ok(())
            }
            Some(s) => self.put(M_STR, s.as_bytes(), name),
        }
    }

    fn int_field(&mut self, v: Option<i64>, name: &'static str) -> R<()> {
        match v {
            None => {
                self.null();
                Ok(())
            }
            Some(n) => self.put(M_INT, n.to_string().as_bytes(), name),
        }
    }

    fn bool_field(&mut self, v: Option<bool>, name: &'static str) -> R<()> {
        match v {
            None => {
                self.null();
                Ok(())
            }
            Some(b) => self.put(M_BOOL, if b { b"1" } else { b"0" }, name),
        }
    }
}

fn as_str<'a>(v: &'a Value, name: &'static str) -> R<Option<&'a str>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s)),
        _ => Err(PreimageError::WrongType(name)),
    }
}

fn as_int(v: &Value, name: &'static str) -> R<Option<i64>> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_i64().map(Some).ok_or(PreimageError::WrongType(name)),
        _ => Err(PreimageError::WrongType(name)),
    }
}

fn as_bool(v: &Value, name: &'static str) -> R<Option<bool>> {
    match v {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => Err(PreimageError::WrongType(name)),
    }
}

/// Expand the vector-file repeat directive (spec 4.2.1). Real documents never
/// carry it; the test vectors do, so oversized content stays reviewable.
fn expand(v: &Value) -> std::borrow::Cow<'_, Value> {
    if let Value::Object(o) = v {
        if let Some(r) = o.get("$repeat") {
            let c = r.get("char").and_then(Value::as_str).unwrap_or("");
            let n = r.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
            return std::borrow::Cow::Owned(Value::String(c.repeat(n)));
        }
    }
    std::borrow::Cow::Borrowed(v)
}

/// Build the preimage for one record.
///
/// `rec` carries the envelope fields (`seq`, `prev_hash`, `id`, `timestamp_us`)
/// and the body fields for its kind, flat.
pub fn preimage(kind: &str, rec: &Value) -> R<Vec<u8>> {
    let body = schema(kind).ok_or_else(|| PreimageError::UnknownKind(kind.to_string()))?;
    let count = field_count(kind).unwrap();
    let mut b = Buf { out: Vec::with_capacity(512) };

    let get = |n: &'static str| -> R<&Value> { rec.get(n).ok_or(PreimageError::MissingField(n)) };

    b.str_field(Some(TAG), "tag")?;
    b.int_field(Some(count), "field_count")?;
    b.int_field(Some(as_int(get("seq")?, "seq")?.ok_or(PreimageError::MissingField("seq"))?), "seq")?;
    b.str_field(
        Some(as_str(get("prev_hash")?, "prev_hash")?.ok_or(PreimageError::MissingField("prev_hash"))?),
        "prev_hash",
    )?;
    b.str_field(Some(kind), "event_kind")?;
    b.str_field(Some(as_str(get("id")?, "id")?.ok_or(PreimageError::MissingField("id"))?), "id")?;
    b.int_field(
        Some(as_int(get("timestamp_us")?, "timestamp_us")?.ok_or(PreimageError::MissingField("timestamp_us"))?),
        "timestamp_us",
    )?;

    for (name, ty) in body {
        let raw = get(name)?;
        let v = expand(raw);
        // Section 7 rule 1: a field that violates its declared nullability is a
        // hard failure. `decision` is not nullable (section 4.4). Without this a
        // NULL decision encodes as the one-byte NULL marker, hashes, and
        // verifies. Rule 1 covers every non-nullable field; this implementation
        // enforces it for `decision` only. A missing `decision` already fails
        // at `get` above.
        if kind == "gate_decision" && *name == "decision" && v.is_null() {
            return Err(PreimageError::NullField(name));
        }
        match ty {
            Ty::Str => b.str_field(as_str(&v, name)?, name)?,
            Ty::Int => b.int_field(as_int(&v, name)?, name)?,
            Ty::Bool => b.bool_field(as_bool(&v, name)?, name)?,
            Ty::ArrStr | Ty::ArrInt => match &*v {
                Value::Null => b.null(),
                Value::Array(items) => {
                    if items.len() > MAX_ARRAY_ELEMS {
                        return Err(PreimageError::ArrayTooLarge(name, items.len()));
                    }
                    if *name == "features_canonical" && items.len() != 27 {
                        return Err(PreimageError::BadFeatureArity(items.len()));
                    }
                    b.out.push(M_ARR);
                    b.out.extend_from_slice(&(items.len() as u32).to_be_bytes());
                    for it in items {
                        if *ty == Ty::ArrStr {
                            b.str_field(as_str(it, name)?, name)?;
                        } else {
                            b.int_field(as_int(it, name)?, name)?;
                        }
                    }
                }
                _ => return Err(PreimageError::WrongType(name)),
            },
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

/// Whether this record's own content is covered by its hash.
///
/// Only `interaction` records carry content. A v1 record covers none of it,
/// which is the whole reason for 2.0, and the verifier says so per record.
pub fn content_covered(kind: &str, rec: &Value) -> bool {
    kind == "interaction"
        && (rec.get("user_message").is_some() || rec.get("ai_response").is_some())
}
