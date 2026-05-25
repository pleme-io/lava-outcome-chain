//! [`OutcomeSink`] — the persistence abstraction.
//!
//! Every consumer interacts with the chain through this trait; the
//! concrete impls swap freely. Three ship in this crate:
//!
//!   - [`InMemorySink`] — `Vec<Receipt>`-backed, the testing default.
//!   - [`FilesystemSink`] — one JSON file per receipt under a typed
//!     directory layout: `<base>/<resource-key>/<sequence>.json`.
//!   - [`NullSink`] — drops every receipt; useful in dev clusters
//!     where attestation is intentionally out of scope.
//!
//! Future impls (S3 / MinIO / object_store / SQLite / Postgres / a
//! magma-state-backed sink) implement this same trait — chain code
//! never changes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::receipt::{Payload, Receipt};

/// The append-only sink trait. Implementations must guarantee:
/// 1. `append` is total-order — every receipt comes back from
///    `read_all` in append order.
/// 2. `tail` returns the most-recently appended receipt or `None`
///    on empty.
/// 3. `len` matches `read_all().len()` (consistency check used by
///    verifiers).
pub trait OutcomeSink<P: Payload>: Send {
    /// Append one receipt to the tail.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`SinkError`].
    fn append(&mut self, receipt: Receipt<P>) -> Result<(), SinkError>;

    /// Read every receipt currently persisted, in append order.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`SinkError`].
    fn read_all(&self) -> Result<Vec<Receipt<P>>, SinkError>;

    /// Tail receipt (highest sequence). `None` on empty.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`SinkError`].
    fn tail(&self) -> Result<Option<Receipt<P>>, SinkError> {
        Ok(self.read_all()?.into_iter().last())
    }

    /// Total receipts persisted.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`SinkError`].
    fn len(&self) -> Result<usize, SinkError> {
        Ok(self.read_all()?.len())
    }

    /// Convenience for callers that want `is_empty()` semantics.
    ///
    /// # Errors
    /// Surfaces backend-specific failures as [`SinkError`].
    fn is_empty(&self) -> Result<bool, SinkError> {
        Ok(self.len()? == 0)
    }
}

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("io: {0}")]
    Io(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("sink invariant: {0}")]
    Invariant(String),
}

// ─── InMemorySink ──────────────────────────────────────────────────

/// `Vec<Receipt>`-backed sink. Wraps the inner vec in `Arc<Mutex>` so
/// it satisfies `Send` + can be cloned across threads.
pub struct InMemorySink<P: Payload> {
    inner: Arc<Mutex<Vec<Receipt<P>>>>,
}

impl<P: Payload> Default for InMemorySink<P> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<P: Payload> Clone for InMemorySink<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Payload> OutcomeSink<P> for InMemorySink<P> {
    fn append(&mut self, receipt: Receipt<P>) -> Result<(), SinkError> {
        let mut v = self
            .inner
            .lock()
            .map_err(|e| SinkError::Invariant(format!("poisoned mutex: {e}")))?;
        v.push(receipt);
        Ok(())
    }
    fn read_all(&self) -> Result<Vec<Receipt<P>>, SinkError> {
        let v = self
            .inner
            .lock()
            .map_err(|e| SinkError::Invariant(format!("poisoned mutex: {e}")))?;
        Ok(v.clone())
    }
}

// ─── FilesystemSink ────────────────────────────────────────────────

/// One JSON file per receipt under
/// `<base_dir>/<resource_key>/<sequence_padded>.json`. The resource
/// key isolates chains per LavaArchitecture so a single base dir can
/// host every chain for a cluster.
pub struct FilesystemSink<P: Payload> {
    base_dir: PathBuf,
    resource_key: String,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: Payload> FilesystemSink<P> {
    /// Build a sink writing to `<base_dir>/<resource_key>/`. Creates
    /// the directory on construction.
    ///
    /// # Errors
    /// Returns [`SinkError::Io`] if directory creation fails.
    pub fn new(
        base_dir: impl Into<PathBuf>,
        resource_key: impl Into<String>,
    ) -> Result<Self, SinkError> {
        let base_dir = base_dir.into();
        let resource_key = resource_key.into();
        std::fs::create_dir_all(base_dir.join(&resource_key))
            .map_err(|e| SinkError::Io(format!("mkdir: {e}")))?;
        Ok(Self {
            base_dir,
            resource_key,
            _phantom: std::marker::PhantomData,
        })
    }

    fn chain_dir(&self) -> PathBuf {
        self.base_dir.join(&self.resource_key)
    }

    fn receipt_path(&self, sequence: u64) -> PathBuf {
        self.chain_dir().join(format!("{sequence:020}.json"))
    }

    fn enumerate_files(&self) -> Result<Vec<PathBuf>, SinkError> {
        let dir = self.chain_dir();
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| SinkError::Io(format!("read_dir({}): {e}", dir.display())))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        files.sort();
        Ok(files)
    }
}

impl<P: Payload> OutcomeSink<P> for FilesystemSink<P> {
    fn append(&mut self, receipt: Receipt<P>) -> Result<(), SinkError> {
        let path = self.receipt_path(receipt.sequence);
        let bytes = serde_json::to_vec_pretty(&receipt)
            .map_err(|e| SinkError::Encode(format!("{e}")))?;
        std::fs::write(&path, bytes)
            .map_err(|e| SinkError::Io(format!("write {}: {e}", path.display())))
    }
    fn read_all(&self) -> Result<Vec<Receipt<P>>, SinkError> {
        let mut out = Vec::new();
        for path in self.enumerate_files()? {
            let bytes = std::fs::read(&path)
                .map_err(|e| SinkError::Io(format!("read {}: {e}", path.display())))?;
            let r: Receipt<P> = serde_json::from_slice(&bytes)
                .map_err(|e| SinkError::Decode(format!("{}: {e}", path.display())))?;
            out.push(r);
        }
        Ok(out)
    }
    fn tail(&self) -> Result<Option<Receipt<P>>, SinkError> {
        let files = self.enumerate_files()?;
        let Some(last) = files.last() else { return Ok(None) };
        let bytes = std::fs::read(last).map_err(|e| SinkError::Io(format!("{e}")))?;
        let r: Receipt<P> = serde_json::from_slice(&bytes)
            .map_err(|e| SinkError::Decode(format!("{e}")))?;
        Ok(Some(r))
    }
    fn len(&self) -> Result<usize, SinkError> {
        Ok(self.enumerate_files()?.len())
    }
}

// ─── NullSink ──────────────────────────────────────────────────────

/// Sink that accepts every receipt + returns nothing. Useful in dev
/// clusters where attestation is intentionally out of scope.
pub struct NullSink<P: Payload>(std::marker::PhantomData<P>);

impl<P: Payload> Default for NullSink<P> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<P: Payload> OutcomeSink<P> for NullSink<P> {
    fn append(&mut self, _receipt: Receipt<P>) -> Result<(), SinkError> {
        Ok(())
    }
    fn read_all(&self) -> Result<Vec<Receipt<P>>, SinkError> {
        Ok(vec![])
    }
}

/// Helper: derive a stable resource key from a [`Path`]-friendly
/// dotted identifier (e.g. `rio/infra/prod-vpc` →
/// `rio-infra-prod-vpc`).
#[must_use]
pub fn resource_key_from_dotted(dotted: &str) -> String {
    dotted.replace('/', "-").replace([' ', ':'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{ChangeSummary, OutcomePayload, ResourceAddress};
    use crate::signing::Signature;

    fn sample() -> Receipt<OutcomePayload> {
        Receipt {
            sequence: 0,
            timestamp: chrono::Utc::now(),
            kind: OutcomePayload::KIND.to_string(),
            prev_hash: crate::hash::ContentHash::genesis(),
            payload: OutcomePayload {
                resource: ResourceAddress::new("c", "n", "x"),
                spec_hash: crate::hash::ContentHash::of(b"s"),
                terraform_json_hash: crate::hash::ContentHash::of(b"t"),
                plan_id: None,
                phase: "Synthesized".into(),
                change_summary: ChangeSummary::default(),
                diagnostics: vec![],
            },
            signature: Signature::None,
            content_hash: crate::hash::ContentHash::of(b"c"),
        }
    }

    #[test]
    fn in_memory_sink_appends_and_reads_in_order() {
        let mut s = InMemorySink::<OutcomePayload>::default();
        let mut r0 = sample();
        r0.sequence = 0;
        let mut r1 = sample();
        r1.sequence = 1;
        s.append(r0).unwrap();
        s.append(r1).unwrap();
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].sequence, 0);
        assert_eq!(all[1].sequence, 1);
        assert_eq!(s.tail().unwrap().unwrap().sequence, 1);
    }

    #[test]
    fn in_memory_sink_empty_invariants() {
        let s = InMemorySink::<OutcomePayload>::default();
        assert_eq!(s.len().unwrap(), 0);
        assert!(s.is_empty().unwrap());
        assert!(s.tail().unwrap().is_none());
    }

    #[test]
    fn filesystem_sink_round_trips_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FilesystemSink::<OutcomePayload>::new(dir.path(), "rio-infra-prod").unwrap();
        let r = sample();
        s.append(r.clone()).unwrap();
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sequence, r.sequence);
        assert_eq!(all[0].payload.resource.namespace, "n");
    }

    #[test]
    fn filesystem_sink_uses_padded_sequence_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FilesystemSink::<OutcomePayload>::new(dir.path(), "rio").unwrap();
        let mut r = sample();
        r.sequence = 42;
        s.append(r).unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path().join("rio"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(files.len(), 1);
        assert!(files[0].starts_with("000"));
        assert!(files[0].ends_with("42.json"));
    }

    #[test]
    fn null_sink_swallows_and_reads_empty() {
        let mut s = NullSink::<OutcomePayload>::default();
        s.append(sample()).unwrap();
        assert_eq!(s.read_all().unwrap().len(), 0);
        assert!(s.tail().unwrap().is_none());
    }

    #[test]
    fn resource_key_helper_replaces_unsafe_path_chars() {
        assert_eq!(resource_key_from_dotted("rio/infra/prod"), "rio-infra-prod");
        assert_eq!(resource_key_from_dotted("a b:c"), "a-b-c");
    }
}
