//! Fact ID: content-addressed 32-byte identifier via SHA-256 of canonical JSON (RFC 8785/JCS)
//!
//! A FactId is the SHA-256 hash of the JSON Canonicalization Scheme (JCS) representation
//! of a JSON value. This provides a deterministic, content-addressed identifier for facts.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte content-addressed fact identifier.
/// 
/// Computed as SHA-256 of the RFC 8785 (JCS) canonical JSON representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FactId([u8; 32]);

impl FactId {
    /// Create a FactId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a FactId from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Compute the FactId for a serializable value.
    pub fn from_value<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        let json_value = serde_json::to_value(value)?;
        Ok(Self::from_json_value(&json_value))
    }

    /// Compute the FactId for a JSON value.
    pub fn from_json_value(value: &Value) -> Self {
        let canonical = canonicalize_json(value);
        let hash = Sha256::digest(canonical.as_bytes());
        Self(hash.into())
    }

    /// Parse a JSON string and compute its FactId.
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        let value: Value = serde_json::from_str(json)?;
        Ok(Self::from_json_value(&value))
    }

    /// Get the raw bytes of the fact ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the fact ID as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get bit at position (0 = MSB of first byte, 255 = LSB of last byte).
    /// Used for SMT traversal.
    pub fn bit(&self, pos: usize) -> bool {
        assert!(pos < 256, "bit position must be < 256");
        let byte_idx = pos / 8;
        let bit_idx = 7 - (pos % 8);
        (self.0[byte_idx] >> bit_idx) & 1 == 1
    }
}

impl fmt::Debug for FactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FactId({})", self.to_hex())
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8; 32]> for FactId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for FactId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Canonicalize a JSON value according to RFC 8785 (JCS).
/// 
/// Rules:
/// - No whitespace between tokens
/// - Object keys sorted lexicographically (UTF-16 code units)
/// - Numbers: no leading zeros, no trailing zeros after decimal, no positive sign
/// - Strings: minimal escaping, \uXXXX for control chars
fn canonicalize_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            out.push_str(&canonicalize_number(n));
        }
        Value::String(s) => {
            write_canonical_string(s, out);
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            out.push('{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| compare_utf16(a, b));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_string(key, out);
                out.push(':');
                write_canonical(&obj[*key], out);
            }
            out.push('}');
        }
    }
}

/// Compare strings by UTF-16 code units (JCS requirement).
fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let a_units: Vec<u16> = a.encode_utf16().collect();
    let b_units: Vec<u16> = b.encode_utf16().collect();
    a_units.cmp(&b_units)
}

/// Canonicalize a number per JCS rules.
fn canonicalize_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        if f == 0.0 {
            return "0".to_string();
        }
        if f.is_infinite() || f.is_nan() {
            return "null".to_string();
        }
        let s = format!("{:e}", f);
        normalize_exp_notation(&s)
    } else {
        n.to_string()
    }
}

/// Normalize exponential notation per JCS.
fn normalize_exp_notation(s: &str) -> String {
    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let exp_part = &s[e_pos + 1..];
        let exp: i32 = exp_part.parse().unwrap_or(0);
        
        if exp.abs() < 21 {
            if let Ok(f) = s.parse::<f64>() {
                let formatted = format!("{}", f);
                if !formatted.contains('e') && !formatted.contains('E') {
                    return formatted;
                }
            }
        }
        
        let clean_mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        let clean_mantissa = if clean_mantissa.is_empty() || clean_mantissa == "-" {
            if mantissa.starts_with('-') { "-0" } else { "0" }
        } else {
            clean_mantissa
        };
        
        if exp == 0 {
            clean_mantissa.to_string()
        } else {
            format!("{}e{:+}", clean_mantissa, exp)
        }
    } else {
        s.to_string()
    }
}

/// Write a canonical JSON string.
fn write_canonical_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if c < ' ' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fact_id_deterministic() {
        let value = json!({"name": "test", "value": 42});
        let id1 = FactId::from_json_value(&value);
        let id2 = FactId::from_json_value(&value);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_fact_id_different_for_different_values() {
        let v1 = json!({"a": 1});
        let v2 = json!({"a": 2});
        assert_ne!(FactId::from_json_value(&v1), FactId::from_json_value(&v2));
    }

    #[test]
    fn test_canonical_key_order() {
        let v1 = json!({"b": 1, "a": 2});
        let v2 = json!({"a": 2, "b": 1});
        assert_eq!(FactId::from_json_value(&v1), FactId::from_json_value(&v2));
    }

    #[test]
    fn test_canonical_json_no_whitespace() {
        let value = json!({"key": "value"});
        let canonical = canonicalize_json(&value);
        assert!(!canonical.contains(' '));
        assert_eq!(canonical, r#"{"key":"value"}"#);
    }

    #[test]
    fn test_canonical_json_sorted_keys() {
        let value = json!({"z": 1, "a": 2, "m": 3});
        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let value = json!({"outer": {"b": 2, "a": 1}});
        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#"{"outer":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_canonical_json_array() {
        let value = json!([3, 1, 2]);
        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, "[3,1,2]");
    }

    #[test]
    fn test_canonical_json_primitives() {
        assert_eq!(canonicalize_json(&json!(null)), "null");
        assert_eq!(canonicalize_json(&json!(true)), "true");
        assert_eq!(canonicalize_json(&json!(false)), "false");
        assert_eq!(canonicalize_json(&json!(42)), "42");
        assert_eq!(canonicalize_json(&json!("hello")), r#""hello""#);
    }

    #[test]
    fn test_fact_id_hex_roundtrip() {
        let value = json!({"test": true});
        let id = FactId::from_json_value(&value);
        let hex = id.to_hex();
        let id2 = FactId::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_fact_id_bit_extraction() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b10110100;
        let id = FactId::from_bytes(bytes);
        
        assert!(id.bit(0));   // 1
        assert!(!id.bit(1));  // 0
        assert!(id.bit(2));   // 1
        assert!(id.bit(3));   // 1
        assert!(!id.bit(4));  // 0
        assert!(id.bit(5));   // 1
        assert!(!id.bit(6));  // 0
        assert!(!id.bit(7));  // 0
    }

    #[test]
    fn test_string_escaping() {
        let value = json!("line1\nline2\ttab");
        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#""line1\nline2\ttab""#);
    }

    #[test]
    fn test_from_json_str() {
        let id = FactId::from_json_str(r#"{"a": 1}"#).unwrap();
        let expected = FactId::from_json_value(&json!({"a": 1}));
        assert_eq!(id, expected);
    }
}
