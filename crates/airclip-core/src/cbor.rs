//! CBOR map helpers. PROTOCOL.md uses integer-keyed maps for every payload (ADR-5), and
//! serde's derive is a poor fit for that: it wants named fields and gives weak errors on
//! wrong types. These builders/readers keep the wire shape explicit and legible next to
//! the spec.
//!
//! Discipline from ADR-5: keys are append-only. Never reuse an integer key.

use std::collections::BTreeMap;

use ciborium::value::{Integer, Value};

use crate::error::{Error, Result};

fn cbor_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Cbor(e.to_string())
}

/// Builds an integer-keyed CBOR map.
#[derive(Debug, Default)]
pub struct MapBuilder {
    entries: Vec<(Value, Value)>,
}

impl MapBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bytes(mut self, key: u64, v: &[u8]) -> Self {
        self.entries
            .push((Value::Integer(key.into()), Value::Bytes(v.to_vec())));
        self
    }

    pub fn text(mut self, key: u64, v: &str) -> Self {
        self.entries
            .push((Value::Integer(key.into()), Value::Text(v.to_owned())));
        self
    }

    pub fn u64(mut self, key: u64, v: u64) -> Self {
        self.entries
            .push((Value::Integer(key.into()), Value::Integer(v.into())));
        self
    }

    pub fn array(mut self, key: u64, v: Vec<Value>) -> Self {
        self.entries
            .push((Value::Integer(key.into()), Value::Array(v)));
        self
    }

    pub fn value(mut self, key: u64, v: Value) -> Self {
        self.entries.push((Value::Integer(key.into()), v));
        self
    }

    pub fn build(self) -> Value {
        Value::Map(self.entries)
    }

    pub fn to_vec(self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(&self.build(), &mut out).map_err(cbor_err)?;
        Ok(out)
    }
}

/// Reads an integer-keyed CBOR map with typed accessors.
#[derive(Debug)]
pub struct MapReader {
    entries: BTreeMap<i128, Value>,
}

impl MapReader {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let v: Value = ciborium::from_reader(bytes).map_err(cbor_err)?;
        Self::from_value(v)
    }

    pub fn from_value(v: Value) -> Result<Self> {
        let Value::Map(pairs) = v else {
            return Err(Error::Cbor("expected a CBOR map".into()));
        };
        let mut entries = BTreeMap::new();
        for (k, val) in pairs {
            let Value::Integer(i) = k else {
                return Err(Error::Cbor("map keys must be integers".into()));
            };
            // Duplicate keys are a malformed payload, not a last-wins merge.
            if entries.insert(i128::from(i), val).is_some() {
                return Err(Error::Cbor("duplicate map key".into()));
            }
        }
        Ok(Self { entries })
    }

    fn get(&self, key: u64) -> Result<&Value> {
        self.entries
            .get(&i128::from(key))
            .ok_or_else(|| Error::Cbor(format!("missing key {key}")))
    }

    pub fn bytes(&self, key: u64) -> Result<&[u8]> {
        match self.get(key)? {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error::Cbor(format!("key {key} is not bytes"))),
        }
    }

    /// Fixed-width byte field — the common case for keys, ids and MACs.
    pub fn byte_array<const N: usize>(&self, key: u64) -> Result<[u8; N]> {
        let b = self.bytes(key)?;
        b.try_into()
            .map_err(|_| Error::Cbor(format!("key {key} must be {N} bytes, got {}", b.len())))
    }

    pub fn text(&self, key: u64) -> Result<&str> {
        match self.get(key)? {
            Value::Text(s) => Ok(s),
            _ => Err(Error::Cbor(format!("key {key} is not text"))),
        }
    }

    pub fn u64(&self, key: u64) -> Result<u64> {
        match self.get(key)? {
            Value::Integer(i) => {
                u64::try_from(*i).map_err(|_| Error::Cbor(format!("key {key} out of u64 range")))
            }
            _ => Err(Error::Cbor(format!("key {key} is not an integer"))),
        }
    }

    pub fn array(&self, key: u64) -> Result<&[Value]> {
        match self.get(key)? {
            Value::Array(a) => Ok(a),
            _ => Err(Error::Cbor(format!("key {key} is not an array"))),
        }
    }

    pub fn has(&self, key: u64) -> bool {
        self.entries.contains_key(&i128::from(key))
    }
}

/// Encode a standalone value (used for array elements).
pub fn to_vec(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(cbor_err)?;
    Ok(out)
}

pub fn int(v: u64) -> Integer {
    v.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_typed_fields() {
        let bytes = MapBuilder::new()
            .bytes(1, &[1, 2, 3])
            .text(2, "phone")
            .u64(3, 42)
            .to_vec()
            .unwrap();

        let r = MapReader::from_slice(&bytes).unwrap();
        assert_eq!(r.bytes(1).unwrap(), &[1, 2, 3]);
        assert_eq!(r.text(2).unwrap(), "phone");
        assert_eq!(r.u64(3).unwrap(), 42);
        assert!(r.has(1));
        assert!(!r.has(9));
    }

    #[test]
    fn byte_array_enforces_width() {
        let bytes = MapBuilder::new().bytes(1, &[0u8; 16]).to_vec().unwrap();
        let r = MapReader::from_slice(&bytes).unwrap();
        assert!(r.byte_array::<16>(1).is_ok());
        assert!(
            r.byte_array::<32>(1).is_err(),
            "wrong width must be rejected"
        );
    }

    #[test]
    fn wrong_type_is_an_error_not_a_default() {
        let bytes = MapBuilder::new().text(1, "not bytes").to_vec().unwrap();
        let r = MapReader::from_slice(&bytes).unwrap();
        assert!(r.bytes(1).is_err());
        assert!(r.u64(1).is_err());
    }

    #[test]
    fn missing_key_is_an_error() {
        let r = MapReader::from_slice(&MapBuilder::new().u64(1, 1).to_vec().unwrap()).unwrap();
        assert!(r.bytes(7).is_err());
    }

    #[test]
    fn rejects_non_map_and_non_integer_keys() {
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Text("nope".into()), &mut buf).unwrap();
        assert!(MapReader::from_slice(&buf).is_err());

        let mut buf = Vec::new();
        let m = Value::Map(vec![(Value::Text("k".into()), Value::Integer(1.into()))]);
        ciborium::into_writer(&m, &mut buf).unwrap();
        assert!(MapReader::from_slice(&buf).is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        let mut buf = Vec::new();
        let m = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
        ]);
        ciborium::into_writer(&m, &mut buf).unwrap();
        assert!(MapReader::from_slice(&buf).is_err());
    }

    #[test]
    fn rejects_trailing_garbage_free_input() {
        // Truncated CBOR must error rather than silently decode a prefix.
        let good = MapBuilder::new().u64(1, 1234567).to_vec().unwrap();
        assert!(MapReader::from_slice(&good[..good.len() - 1]).is_err());
    }
}
