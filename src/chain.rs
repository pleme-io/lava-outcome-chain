//! [`OutcomeChain`] — append-only typed receipt log.
//!
//! Generic over both the payload type and the [`OutcomeSink`]
//! implementation, so test code uses [`crate::sink::InMemorySink`]
//! and production swaps in [`crate::sink::FilesystemSink`] with zero
//! call-site change.
//!
//! Linking is computed for the caller: [`Self::append`] takes a
//! payload, fetches the current tail, computes the prev_hash + the
//! new content_hash, signs, and writes. The caller never assembles
//! receipt fields by hand.

use chrono::Utc;
use thiserror::Error;

use crate::hash::ContentHash;
use crate::receipt::{Payload, Receipt};
use crate::sink::OutcomeSink;
use crate::signing::{SigningError, SigningProvider};

/// The append-only chain primitive. Wraps a sink + a signer and
/// produces typed receipts on every `append`.
pub struct OutcomeChain<P: Payload, S: OutcomeSink<P>, G: SigningProvider> {
    sink: S,
    signer: G,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: Payload, S: OutcomeSink<P>, G: SigningProvider> OutcomeChain<P, S, G> {
    #[must_use]
    pub fn new(sink: S, signer: G) -> Self {
        Self {
            sink,
            signer,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Borrow the sink (useful for snapshot reads / tests).
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Append a new receipt with the supplied payload. The chain
    /// computes `sequence` + `prev_hash` + `content_hash` + signature
    /// internally — callers only think in payloads.
    ///
    /// # Errors
    /// Surfaces [`AppendError`] when the sink read/write or signing
    /// step fails.
    pub fn append(&mut self, payload: P) -> Result<Receipt<P>, AppendError> {
        let tail = self.sink.tail()?;
        let (sequence, prev_hash) = tail.map_or((0u64, ContentHash::genesis()), |t| {
            (t.sequence + 1, t.content_hash)
        });
        let timestamp = Utc::now();
        let content_hash = Receipt::<P>::compute_content_hash(sequence, timestamp, prev_hash, &payload)
            .map_err(|e| AppendError::Encode(e.to_string()))?;
        let signature = self.signer.sign(content_hash.0.as_slice())?;
        let receipt = Receipt {
            sequence,
            timestamp,
            kind: P::KIND.to_string(),
            prev_hash,
            payload,
            signature,
            content_hash,
        };
        self.sink.append(receipt.clone())?;
        Ok(receipt)
    }

    /// Read every receipt currently in the sink. Convenience for
    /// CLI + verifier surfaces.
    ///
    /// # Errors
    /// Surfaces sink read failures.
    pub fn read_all(&self) -> Result<Vec<Receipt<P>>, AppendError> {
        Ok(self.sink.read_all()?)
    }
}

#[derive(Debug, Error)]
pub enum AppendError {
    #[error("encode: {0}")]
    Encode(String),
    #[error("sink: {0}")]
    Sink(#[from] crate::sink::SinkError),
    #[error("sign: {0}")]
    Sign(#[from] SigningError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{ChangeSummary, OutcomePayload, ResourceAddress};
    use crate::signing::NoSigning;
    use crate::sink::InMemorySink;

    fn sample(kind: &str) -> OutcomePayload {
        OutcomePayload {
            resource: ResourceAddress::new("rio", "infra", "demo"),
            spec_hash: ContentHash::of(kind.as_bytes()),
            terraform_json_hash: ContentHash::of(b"json"),
            plan_id: Some("plan-1".into()),
            phase: "Synthesized".into(),
            change_summary: ChangeSummary::default(),
            diagnostics: vec![],
        }
    }

    #[test]
    fn first_append_produces_genesis_receipt() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        let r = chain.append(sample("a")).unwrap();
        assert_eq!(r.sequence, 0);
        assert!(r.prev_hash.is_genesis());
        assert_eq!(r.kind, OutcomePayload::KIND);
    }

    #[test]
    fn subsequent_appends_chain_via_prev_hash() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        let r0 = chain.append(sample("a")).unwrap();
        let r1 = chain.append(sample("b")).unwrap();
        let r2 = chain.append(sample("c")).unwrap();
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);
        assert_eq!(r1.prev_hash, r0.content_hash);
        assert_eq!(r2.prev_hash, r1.content_hash);
    }

    #[test]
    fn append_writes_through_to_sink() {
        let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
        chain.append(sample("a")).unwrap();
        chain.append(sample("b")).unwrap();
        let all = chain.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].sequence, 0);
        assert_eq!(all[1].sequence, 1);
    }
}
