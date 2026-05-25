//! Typed BLAKE3 content addressing.
//!
//! [`ContentHash`] wraps a 32-byte BLAKE3 digest with a typed surface
//! that's serde-friendly (hex string in JSON, raw bytes in memory) and
//! constant-time comparable. The hash IS the receipt's identity —
//! `Receipt::content_hash()` is the canonical reference every downstream
//! consumer holds.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte BLAKE3 digest. Serialized as a 64-char lowercase hex
/// string so receipts are inspectable in plain JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Hash arbitrary bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Hash any serializable value via its canonical JSON encoding.
    ///
    /// # Errors
    /// Surfaces serialization failures.
    pub fn of_value<T: Serialize>(v: &T) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(v)?;
        Ok(Self::of(&bytes))
    }

    /// Genesis sentinel — every linked chain's first receipt names
    /// this as its `prev_hash` so the verifier has a stable starting
    /// invariant (`prev == ZERO` ↔ this is the genesis receipt).
    #[must_use]
    pub const fn genesis() -> Self {
        Self([0u8; 32])
    }

    /// Is this the genesis sentinel (all-zero)?
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Hex-encoded representation (64 chars, lowercase). Used in CLI
    /// output + receipt JSON.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentHash({}…)", &self.hex()[..16])
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "ContentHash expected 32 bytes (64 hex chars), got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn of_is_deterministic() {
        let a = ContentHash::of(b"hello");
        let b = ContentHash::of(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn of_distinguishes_distinct_inputs() {
        assert_ne!(ContentHash::of(b"a"), ContentHash::of(b"b"));
    }

    #[test]
    fn genesis_is_all_zero() {
        assert!(ContentHash::genesis().is_genesis());
        assert!(!ContentHash::of(b"non-genesis").is_genesis());
    }

    #[test]
    fn hex_round_trips_through_serde() {
        let h = ContentHash::of(b"data");
        let j = serde_json::to_string(&h).unwrap();
        let parsed: ContentHash = serde_json::from_str(&j).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn hex_is_64_chars_lowercase() {
        let h = ContentHash::of(b"data");
        let s = h.hex();
        assert_eq!(s.len(), 64);
        assert_eq!(s, s.to_lowercase());
    }
}
