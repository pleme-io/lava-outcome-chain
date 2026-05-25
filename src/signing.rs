//! Pluggable signing layer.
//!
//! Every [`Receipt`](crate::Receipt) optionally carries a typed
//! [`Signature`] produced by a [`SigningProvider`]. The default
//! provider is [`NoSigning`] (zero-overhead, tests + dev). The
//! production provider is [`Ed25519Signer`] (32-byte secret, 64-byte
//! signature, ed25519-dalek backed).
//!
//! The verifier is the dual surface — [`SignatureVerifier`] is the
//! trait every consumer uses to validate a chain. The two concrete
//! impls are [`NoOpVerifier`] (accepts everything; matches
//! `NoSigning`) and [`Ed25519Verifier`] (validates against a known
//! public key).
//!
//! Solid abstraction: chain code never mentions ed25519. Replacing
//! Ed25519 with another scheme later means a new pair of impls, not a
//! chain rewrite.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A typed signature. Variants name the algorithm so future schemes
/// don't break existing chain JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algo", rename_all = "kebab-case")]
pub enum Signature {
    /// No signature attached. Used by [`NoSigning`].
    None,
    /// Ed25519, 64-byte signature, hex-encoded.
    Ed25519 {
        /// 64-byte signature (hex).
        sig: String,
        /// 32-byte public verifying key (hex). Lets verifiers do
        /// per-receipt key rotation without an out-of-band key
        /// distribution channel.
        public_key: String,
    },
}

impl Signature {
    /// Is this signature anything other than [`Self::None`]?
    #[must_use]
    pub fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// The signing side of the abstraction. Implementations sign a
/// content hash; the verifier is the dual.
pub trait SigningProvider: Send + Sync {
    /// Produce a [`Signature`] over the supplied bytes (typically the
    /// receipt's content_hash).
    ///
    /// # Errors
    /// Backend-specific failures surface as [`SigningError`].
    fn sign(&self, content: &[u8]) -> Result<Signature, SigningError>;
}

/// The verifier side of the abstraction.
pub trait SignatureVerifier: Send + Sync {
    /// Validate a signature against the bytes that were supposedly
    /// signed.
    ///
    /// # Errors
    /// Returns [`SigningError::Invalid`] when the signature fails to
    /// verify; [`SigningError::Mismatched`] when the verifier doesn't
    /// recognize the signature scheme.
    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), SigningError>;
}

/// Zero-signing impl. Useful in tests + dev clusters where attestation
/// is out of scope; production should use [`Ed25519Signer`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSigning;

impl SigningProvider for NoSigning {
    fn sign(&self, _content: &[u8]) -> Result<Signature, SigningError> {
        Ok(Signature::None)
    }
}

/// Companion verifier for [`NoSigning`]. Accepts both
/// [`Signature::None`] and any present-but-unverified signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpVerifier;

impl SignatureVerifier for NoOpVerifier {
    fn verify(&self, _content: &[u8], _sig: &Signature) -> Result<(), SigningError> {
        Ok(())
    }
}

/// Ed25519-backed signer. Construct via [`Self::generate`] for a
/// fresh keypair or [`Self::from_secret_bytes`] for a known secret.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Build a signer from a 32-byte secret seed.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            key: SigningKey::from_bytes(secret),
        }
    }

    /// Generate a fresh signer with a random keypair. Useful in tests
    /// and one-shot CLIs.
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_secret_bytes(&bytes)
    }

    /// Public verifying key — hand this to the verifier side.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the secret bytes in Debug output.
        f.debug_struct("Ed25519Signer")
            .field("public", &hex::encode(self.verifying_key().to_bytes()))
            .finish_non_exhaustive()
    }
}

impl SigningProvider for Ed25519Signer {
    fn sign(&self, content: &[u8]) -> Result<Signature, SigningError> {
        let sig = self.key.sign(content);
        Ok(Signature::Ed25519 {
            sig: hex::encode(sig.to_bytes()),
            public_key: hex::encode(self.verifying_key().to_bytes()),
        })
    }
}

/// Ed25519-backed verifier. Holds the public key the chain is meant
/// to be signed against.
pub struct Ed25519Verifier {
    pub public_key: VerifyingKey,
}

impl Ed25519Verifier {
    #[must_use]
    pub fn new(public_key: VerifyingKey) -> Self {
        Self { public_key }
    }

    /// Build a verifier from a 32-byte public key.
    ///
    /// # Errors
    /// Returns [`SigningError::Invalid`] when the bytes don't decode
    /// to a valid Ed25519 public key.
    pub fn from_public_bytes(bytes: &[u8; 32]) -> Result<Self, SigningError> {
        let vk = VerifyingKey::from_bytes(bytes)
            .map_err(|e| SigningError::Invalid(format!("bad public key: {e}")))?;
        Ok(Self::new(vk))
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), SigningError> {
        let Signature::Ed25519 { sig, public_key } = sig else {
            return Err(SigningError::Mismatched(
                "expected Ed25519, got different scheme".into(),
            ));
        };
        // Confirm the receipt's embedded public key matches what we
        // were configured for — defense in depth against an attacker
        // signing receipts with their own key and embedding it.
        let pk_bytes = hex::decode(public_key)
            .map_err(|e| SigningError::Invalid(format!("public_key hex: {e}")))?;
        if pk_bytes != self.public_key.to_bytes() {
            return Err(SigningError::Mismatched(format!(
                "receipt public_key {} does not match verifier public_key {}",
                public_key,
                hex::encode(self.public_key.to_bytes())
            )));
        }
        let sig_bytes = hex::decode(sig)
            .map_err(|e| SigningError::Invalid(format!("sig hex: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(SigningError::Invalid(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut s = [0u8; 64];
        s.copy_from_slice(&sig_bytes);
        let sig_typed = ed25519_dalek::Signature::from_bytes(&s);
        self.public_key
            .verify(content, &sig_typed)
            .map_err(|e| SigningError::Invalid(format!("ed25519 verify: {e}")))
    }
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid signature: {0}")]
    Invalid(String),
    #[error("signature scheme mismatch: {0}")]
    Mismatched(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signing_produces_none_variant() {
        let s = NoSigning.sign(b"x").unwrap();
        assert_eq!(s, Signature::None);
        assert!(!s.is_some());
    }

    #[test]
    fn no_op_verifier_accepts_everything() {
        NoOpVerifier.verify(b"x", &Signature::None).unwrap();
        NoOpVerifier
            .verify(
                b"x",
                &Signature::Ed25519 {
                    sig: "ff".repeat(64),
                    public_key: "00".repeat(32),
                },
            )
            .unwrap();
    }

    #[test]
    fn ed25519_round_trips_sign_and_verify() {
        let signer = Ed25519Signer::generate();
        let verifier = Ed25519Verifier::new(signer.verifying_key());
        let payload = b"reconcile-tick-payload";
        let sig = signer.sign(payload).unwrap();
        assert!(sig.is_some());
        verifier.verify(payload, &sig).unwrap();
    }

    #[test]
    fn ed25519_rejects_tampered_payload() {
        let signer = Ed25519Signer::generate();
        let verifier = Ed25519Verifier::new(signer.verifying_key());
        let sig = signer.sign(b"original").unwrap();
        let err = verifier.verify(b"TAMPERED", &sig).unwrap_err();
        matches!(err, SigningError::Invalid(_));
    }

    #[test]
    fn ed25519_rejects_unknown_public_key() {
        let signer = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let verifier = Ed25519Verifier::new(other.verifying_key());
        let sig = signer.sign(b"payload").unwrap();
        let err = verifier.verify(b"payload", &sig).unwrap_err();
        matches!(err, SigningError::Mismatched(_));
    }

    #[test]
    fn ed25519_signer_debug_does_not_leak_secret() {
        let signer = Ed25519Signer::generate();
        let dbg = format!("{signer:?}");
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(dbg.contains("public"));
    }

    #[test]
    fn signature_serializes_with_typed_algo_tag() {
        let sig = Signature::Ed25519 {
            sig: "aa".repeat(64),
            public_key: "bb".repeat(32),
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains(r#""algo":"ed25519""#));
    }
}
