//! Typed receipt — one entry per reconcile tick.
//!
//! [`Receipt`] is generic over the [`Payload`] type so the same chain
//! shape carries different per-tick info for different controllers:
//!
//!   - [`crate::OutcomePayload`] — lava-operator reconcile outcomes
//!   - Future: AnomalyPayload, PromessaPayload, etc.
//!
//! The receipt's identity is its `content_hash`, computed over every
//! field except the `signature` (so a signature can be appended
//! without changing what was signed).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::signing::Signature;

/// Trait every receipt-body type implements. Solid abstraction: the
/// chain machinery never reaches into the payload — it only computes
/// its hash + serializes it.
pub trait Payload:
    Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + std::fmt::Debug
{
    /// Stable kind tag — surfaces in the receipt for cross-payload
    /// routing on read.
    const KIND: &'static str;
}

/// The canonical lava reconcile-tick payload. Shipped as the first
/// concrete consumer of the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomePayload {
    /// Cluster + namespace + name address.
    pub resource: ResourceAddress,
    /// Hash of the LavaArchitecture spec at this tick.
    pub spec_hash: ContentHash,
    /// Hash of the rendered terraform.json.
    pub terraform_json_hash: ContentHash,
    /// Magma's plan_id (BLAKE3 of the typed Plan).
    pub plan_id: Option<String>,
    /// Typed phase string (Pending|Synthesized|Planned|Applied|Drifted|
    /// Reconverging|Failed). Kept as a string here to keep this
    /// crate dependency-light; lava-operator owns the enum.
    pub phase: String,
    /// Per-resource diff summary — Create/Update/Delete counts.
    #[serde(default)]
    pub change_summary: ChangeSummary,
    /// Free-text diagnostic surface; structured fields go elsewhere.
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl Payload for OutcomePayload {
    const KIND: &'static str = "lava.outcome";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAddress {
    pub cluster: String,
    pub namespace: String,
    pub name: String,
}

impl ResourceAddress {
    #[must_use]
    pub fn new(
        cluster: impl Into<String>,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            cluster: cluster.into(),
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Dotted form: `<cluster>/<namespace>/<name>`. Used in OutcomeChain
    /// keys + log messages.
    #[must_use]
    pub fn dotted(&self) -> String {
        format!("{}/{}/{}", self.cluster, self.namespace, self.name)
    }
}

/// Per-tick change summary — counts only; full ResourceChange list
/// stays inside magma's Plan structure.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeSummary {
    pub create: u32,
    pub update: u32,
    pub delete: u32,
    pub no_op: u32,
}

impl ChangeSummary {
    #[must_use]
    pub fn total(&self) -> u32 {
        self.create + self.update + self.delete + self.no_op
    }
    /// Are there any non-NoOp changes (drift / pending apply)?
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.create + self.update + self.delete > 0
    }
}

/// One linked entry in the chain. Generic over the payload; the
/// machinery doesn't care what `P` is as long as it's `Payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", bound = "P: Payload")]
pub struct Receipt<P: Payload> {
    /// Monotonic sequence — starts at 0 (genesis) and increments by 1.
    pub sequence: u64,
    /// Wall-clock timestamp when this receipt was sealed.
    pub timestamp: DateTime<Utc>,
    /// Stable kind tag for cross-payload chains.
    pub kind: String,
    /// Hash of the previous receipt's `content_hash`. Genesis uses
    /// [`ContentHash::genesis`].
    pub prev_hash: ContentHash,
    /// The typed per-tick body.
    pub payload: P,
    /// Optional signature over `content_hash`. [`Signature::None`]
    /// when [`crate::signing::NoSigning`] is in use.
    #[serde(default = "default_signature")]
    pub signature: Signature,
    /// BLAKE3 of every field above (excluding `signature` itself).
    pub content_hash: ContentHash,
}

fn default_signature() -> Signature {
    Signature::None
}

/// Helper used by chain code to compute the canonical pre-hash bytes
/// for a receipt. Excludes the signature field by construction (it's
/// not present in this intermediate value).
#[derive(Serialize)]
#[serde(rename_all = "camelCase", bound = "P: Payload")]
struct PreHash<'a, P: Payload> {
    sequence: u64,
    timestamp: DateTime<Utc>,
    kind: &'a str,
    prev_hash: ContentHash,
    payload: &'a P,
}

impl<P: Payload> Receipt<P> {
    /// Compute the canonical content_hash for the supplied fields —
    /// excludes the signature, so signing happens AFTER hashing.
    ///
    /// # Errors
    /// Surfaces serde JSON encoding failures.
    pub(crate) fn compute_content_hash(
        sequence: u64,
        timestamp: DateTime<Utc>,
        prev_hash: ContentHash,
        payload: &P,
    ) -> Result<ContentHash, serde_json::Error> {
        let pre = PreHash {
            sequence,
            timestamp,
            kind: P::KIND,
            prev_hash,
            payload,
        };
        ContentHash::of_value(&pre)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_summary_total_and_has_changes() {
        let mut s = ChangeSummary::default();
        assert_eq!(s.total(), 0);
        assert!(!s.has_changes());
        s.create = 2;
        s.no_op = 5;
        assert_eq!(s.total(), 7);
        assert!(s.has_changes());
        s.create = 0;
        assert!(!s.has_changes());
    }

    #[test]
    fn resource_address_dotted_form() {
        let a = ResourceAddress::new("rio", "infra", "prod-vpc");
        assert_eq!(a.dotted(), "rio/infra/prod-vpc");
    }

    #[test]
    fn outcome_payload_kind_is_stable() {
        assert_eq!(OutcomePayload::KIND, "lava.outcome");
    }

    #[test]
    fn compute_content_hash_excludes_signature_by_construction() {
        // Two equal pre-image fields must produce the same hash
        // regardless of what signature gets attached later.
        let ts = chrono::Utc::now();
        let payload = OutcomePayload {
            resource: ResourceAddress::new("c", "n", "x"),
            spec_hash: ContentHash::of(b"spec"),
            terraform_json_hash: ContentHash::of(b"json"),
            plan_id: Some("plan-1".into()),
            phase: "Applied".into(),
            change_summary: ChangeSummary::default(),
            diagnostics: vec![],
        };
        let h1 = Receipt::<OutcomePayload>::compute_content_hash(
            1,
            ts,
            ContentHash::genesis(),
            &payload,
        )
        .unwrap();
        let h2 = Receipt::<OutcomePayload>::compute_content_hash(
            1,
            ts,
            ContentHash::genesis(),
            &payload,
        )
        .unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_content_hash_responds_to_payload_changes() {
        let ts = chrono::Utc::now();
        let p1 = OutcomePayload {
            resource: ResourceAddress::new("c", "n", "x"),
            spec_hash: ContentHash::of(b"spec-1"),
            terraform_json_hash: ContentHash::of(b"json"),
            plan_id: None,
            phase: "Applied".into(),
            change_summary: ChangeSummary::default(),
            diagnostics: vec![],
        };
        let mut p2 = p1.clone();
        p2.spec_hash = ContentHash::of(b"spec-2");
        let h1 =
            Receipt::<OutcomePayload>::compute_content_hash(1, ts, ContentHash::genesis(), &p1)
                .unwrap();
        let h2 =
            Receipt::<OutcomePayload>::compute_content_hash(1, ts, ContentHash::genesis(), &p2)
                .unwrap();
        assert_ne!(h1, h2);
    }
}
