//! lava-outcome-chain — typed BLAKE3-linked OutcomeChain for IaC
//! reconcile-tick attestation.
//!
//! ## Shape
//!
//! ```text
//! Receipt<P>₀ ──prev_hash──▶ Receipt<P>₁ ──prev_hash──▶ Receipt<P>₂ ─┐
//!   ─ sequence: 0              ─ sequence: 1              ─ sequence: 2  │
//!   ─ prev: ZERO               ─ prev: H(₀)               ─ prev: H(₁)   │
//!   ─ payload (typed P)        ─ payload (typed P)        ─ payload (P)  │
//!   ─ content_hash (BLAKE3)    ─ content_hash             ─ content_hash │
//!   ─ signature (optional)     ─ signature                ─ signature    │
//!                                                                       │
//!                                                              persisted to
//!                                                              OutcomeSink
//! ```
//!
//! ## Solid abstractions
//!
//! - [`Payload`] — receipt-body trait. Per-controller payloads (lava
//!   outcome, future anomaly, future promise) implement once.
//! - [`OutcomeSink`] — persistence trait. Three impls ship:
//!   [`InMemorySink`], [`FilesystemSink`], [`NullSink`].
//! - [`SigningProvider`] / [`SignatureVerifier`] — attestation dual.
//!   Three impls per side: NoSigning/NoOpVerifier (zero-overhead) +
//!   Ed25519Signer/Ed25519Verifier (production).
//! - [`OutcomeChain`] — typed glue. Generic over payload + sink +
//!   signer; callers think in payloads, never in hashes or sequences.
//! - [`verify_chain`] — pure verifier. Walks a chain end-to-end and
//!   reports the first invariant violation as a typed [`VerifyError`].
//!
//! ## First consumer
//!
//! [`OutcomePayload`] is the lava-operator reconcile-tick body. Every
//! reconcile pass appends one receipt; downstream tooling
//! (`kensa verify outcome-chain --lava <name>`) walks the chain to
//! prove what the operator did and when.
//!
//! ## Composing with the rest of the suite
//!
//! - **lava-drift** appends a receipt whose phase is `Drifted` after
//!   every drift-detection scan.
//! - **lava-operator M3** routes typed `LavaAnomaly` CRs through a
//!   second-payload chain — same machinery, different `P`.
//! - **lava-operator M4** (PromessaController) emits an OutcomeReceipt
//!   on every beat of the 7-beat Viggy tick.

#![allow(clippy::module_name_repetitions)]

pub mod chain;
pub mod hash;
pub mod receipt;
pub mod signing;
pub mod sink;
pub mod verify;

pub use chain::{AppendError, OutcomeChain};
pub use hash::ContentHash;
pub use receipt::{ChangeSummary, OutcomePayload, Payload, Receipt, ResourceAddress};
pub use signing::{
    Ed25519Signer, Ed25519Verifier, NoOpVerifier, NoSigning, Signature, SignatureVerifier,
    SigningError, SigningProvider,
};
pub use sink::{
    resource_key_from_dotted, FilesystemSink, InMemorySink, NullSink, OutcomeSink, SinkError,
};
pub use verify::{verify_chain, VerifyError};
