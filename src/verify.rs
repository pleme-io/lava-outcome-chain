//! Chain verifier.
//!
//! [`verify_chain`] walks a sequence of receipts and checks every
//! invariant the chain promises:
//!
//!   1. Sequence numbers start at 0 and increment by 1.
//!   2. Receipt 0's `prev_hash` is the genesis sentinel.
//!   3. Receipt N's `prev_hash` equals receipt N-1's `content_hash`.
//!   4. Each receipt's `content_hash` matches a fresh re-hash of its
//!      fields (no in-place mutation since sealing).
//!   5. Each receipt's `signature` validates under the supplied
//!      [`SignatureVerifier`] (skipped for [`Signature::None`]).
//!   6. Receipt N's timestamp is `>=` receipt N-1's timestamp
//!      (monotonic in clock time too).

use thiserror::Error;

use crate::hash::ContentHash;
use crate::receipt::{Payload, Receipt};
use crate::signing::{SignatureVerifier, SigningError};

/// Walk the supplied chain end-to-end. Returns `Ok(())` only when
/// every invariant holds. On the first violation, returns a typed
/// [`VerifyError`] naming the failing receipt + invariant.
///
/// # Errors
/// See [`VerifyError`].
pub fn verify_chain<P, V>(receipts: &[Receipt<P>], verifier: &V) -> Result<(), VerifyError>
where
    P: Payload,
    V: SignatureVerifier,
{
    let mut prev_hash = ContentHash::genesis();
    let mut prev_timestamp = None;
    for (i, r) in receipts.iter().enumerate() {
        let expected_sequence = u64::try_from(i)
            .map_err(|e| VerifyError::Encode(format!("sequence overflow: {e}")))?;
        if r.sequence != expected_sequence {
            return Err(VerifyError::Sequence {
                at: i,
                expected: expected_sequence,
                actual: r.sequence,
            });
        }
        if r.prev_hash != prev_hash {
            return Err(VerifyError::PrevHashMismatch {
                at: i,
                expected: prev_hash,
                actual: r.prev_hash,
            });
        }
        let recomputed = Receipt::<P>::compute_content_hash(
            r.sequence,
            r.timestamp,
            r.prev_hash,
            &r.payload,
        )
        .map_err(|e| VerifyError::Encode(format!("re-hash receipt {i}: {e}")))?;
        if recomputed != r.content_hash {
            return Err(VerifyError::ContentHashMismatch {
                at: i,
                expected: recomputed,
                actual: r.content_hash,
            });
        }
        if r.signature.is_some() {
            verifier
                .verify(r.content_hash.0.as_slice(), &r.signature)
                .map_err(|source| VerifyError::Signature { at: i, source })?;
        }
        if let Some(prev_ts) = prev_timestamp {
            if r.timestamp < prev_ts {
                return Err(VerifyError::TimestampRegression {
                    at: i,
                    prev: prev_ts,
                    actual: r.timestamp,
                });
            }
        }
        prev_hash = r.content_hash;
        prev_timestamp = Some(r.timestamp);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("receipt {at}: sequence expected {expected}, got {actual}")]
    Sequence { at: usize, expected: u64, actual: u64 },
    #[error("receipt {at}: prev_hash expected {expected}, got {actual}")]
    PrevHashMismatch {
        at: usize,
        expected: ContentHash,
        actual: ContentHash,
    },
    #[error("receipt {at}: content_hash expected {expected}, got {actual}")]
    ContentHashMismatch {
        at: usize,
        expected: ContentHash,
        actual: ContentHash,
    },
    #[error("receipt {at}: signature: {source}")]
    Signature {
        at: usize,
        #[source]
        source: SigningError,
    },
    #[error("receipt {at}: timestamp {actual} regressed below previous {prev}")]
    TimestampRegression {
        at: usize,
        prev: chrono::DateTime<chrono::Utc>,
        actual: chrono::DateTime<chrono::Utc>,
    },
    #[error("encode: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::OutcomeChain;
    use crate::receipt::{ChangeSummary, OutcomePayload, ResourceAddress};
    use crate::signing::{Ed25519Signer, Ed25519Verifier, NoOpVerifier, NoSigning};
    use crate::sink::InMemorySink;

    fn sample(kind: &str) -> OutcomePayload {
        OutcomePayload {
            resource: ResourceAddress::new("rio", "infra", "demo"),
            spec_hash: ContentHash::of(kind.as_bytes()),
            terraform_json_hash: ContentHash::of(b"json"),
            plan_id: None,
            phase: "Synthesized".into(),
            change_summary: ChangeSummary::default(),
            diagnostics: vec![],
        }
    }

    #[test]
    fn three_receipt_chain_verifies_clean() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        chain.append(sample("c")).unwrap();
        let receipts = chain.read_all().unwrap();
        verify_chain(&receipts, &NoOpVerifier).unwrap();
    }

    #[test]
    fn ed25519_signed_chain_verifies_under_matching_verifier() {
        let signer = Ed25519Signer::generate();
        let public = signer.verifying_key();
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), signer);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        let receipts = chain.read_all().unwrap();
        verify_chain(&receipts, &Ed25519Verifier::new(public)).unwrap();
    }

    #[test]
    fn tampered_payload_fails_content_hash_check() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        let mut receipts = chain.read_all().unwrap();
        // Tamper with receipt 1's payload AFTER sealing.
        receipts[1].payload.diagnostics.push("attacker-edit".into());
        let err = verify_chain(&receipts, &NoOpVerifier).unwrap_err();
        matches!(err, VerifyError::ContentHashMismatch { at: 1, .. });
    }

    #[test]
    fn rebroken_prev_hash_link_surfaces_typed_error() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        let mut receipts = chain.read_all().unwrap();
        receipts[1].prev_hash = ContentHash::of(b"forged-prev");
        // Recompute content_hash so we don't trip ContentHashMismatch
        // first — we want PrevHashMismatch specifically.
        receipts[1].content_hash = Receipt::<OutcomePayload>::compute_content_hash(
            receipts[1].sequence,
            receipts[1].timestamp,
            receipts[1].prev_hash,
            &receipts[1].payload,
        )
        .unwrap();
        let err = verify_chain(&receipts, &NoOpVerifier).unwrap_err();
        matches!(err, VerifyError::PrevHashMismatch { at: 1, .. });
    }

    #[test]
    fn sequence_skip_surfaces_typed_error() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        let mut receipts = chain.read_all().unwrap();
        receipts[1].sequence = 5;
        // Recompute hash to bypass ContentHashMismatch.
        receipts[1].content_hash = Receipt::<OutcomePayload>::compute_content_hash(
            5,
            receipts[1].timestamp,
            receipts[1].prev_hash,
            &receipts[1].payload,
        )
        .unwrap();
        let err = verify_chain(&receipts, &NoOpVerifier).unwrap_err();
        matches!(err, VerifyError::Sequence { at: 1, .. });
    }

    #[test]
    fn ed25519_chain_fails_under_different_public_key() {
        let signer = Ed25519Signer::generate();
        let other = Ed25519Signer::generate();
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), signer);
        chain.append(sample("a")).unwrap();
        let receipts = chain.read_all().unwrap();
        let err =
            verify_chain(&receipts, &Ed25519Verifier::new(other.verifying_key())).unwrap_err();
        matches!(err, VerifyError::Signature { at: 0, .. });
    }
}
