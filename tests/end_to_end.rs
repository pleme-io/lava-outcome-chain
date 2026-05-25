//! End-to-end: simulate a 5-tick reconcile chain through every sink
//! impl + sign with Ed25519 + verify clean. Single test that proves
//! every abstraction composes.

use lava_outcome_chain::{
    resource_key_from_dotted, verify_chain, ChangeSummary, Ed25519Signer, Ed25519Verifier,
    FilesystemSink, InMemorySink, NoOpVerifier, NoSigning, NullSink, OutcomeChain, OutcomePayload,
    OutcomeSink, Receipt, ResourceAddress,
};

fn tick(phase: &str, plan_id: u32) -> OutcomePayload {
    OutcomePayload {
        resource: ResourceAddress::new("rio", "infra", "prod-vpc"),
        spec_hash: lava_outcome_chain::ContentHash::of(b"spec-v1"),
        terraform_json_hash: lava_outcome_chain::ContentHash::of(b"tfjson-v1"),
        plan_id: Some(format!("plan-{plan_id}")),
        phase: phase.to_string(),
        change_summary: ChangeSummary {
            create: 1,
            ..Default::default()
        },
        diagnostics: vec![],
    }
}

#[test]
fn in_memory_sink_with_no_signing_round_trips_5_ticks_and_verifies_clean() {
    let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
    for i in 0..5 {
        chain
            .append(tick(
                ["Pending", "Synthesized", "Planned", "Applied", "Drifted"][i],
                i as u32,
            ))
            .unwrap();
    }
    let receipts = chain.read_all().unwrap();
    assert_eq!(receipts.len(), 5);
    verify_chain(&receipts, &NoOpVerifier).unwrap();
}

#[test]
fn filesystem_sink_with_ed25519_signing_round_trips_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate();
    let verifier_key = signer.verifying_key();
    let key = resource_key_from_dotted("rio/infra/prod-vpc");
    let sink = FilesystemSink::<OutcomePayload>::new(dir.path(), &key).unwrap();
    let mut chain = OutcomeChain::new(sink, signer);
    for i in 0..3 {
        chain.append(tick("Applied", i)).unwrap();
    }
    // Re-open through a fresh sink to prove on-disk durability.
    let fresh = FilesystemSink::<OutcomePayload>::new(dir.path(), &key).unwrap();
    let receipts = fresh.read_all().unwrap();
    assert_eq!(receipts.len(), 3);
    verify_chain(&receipts, &Ed25519Verifier::new(verifier_key)).unwrap();
}

#[test]
fn null_sink_chain_appends_succeed_but_persist_nothing() {
    let mut chain = OutcomeChain::new(NullSink::<OutcomePayload>::default(), NoSigning);
    let r0 = chain.append(tick("Applied", 0)).unwrap();
    let r1 = chain.append(tick("Applied", 1)).unwrap();
    // Both receipts get sequence 0 — because NullSink always reads
    // back empty, every append sees tail() == None and starts fresh.
    // This is the documented behavior; consumers that need a real
    // monotonic sequence pair NullSink with InMemorySink, or just
    // use InMemorySink.
    assert_eq!(r0.sequence, 0);
    assert_eq!(r1.sequence, 0);
    assert_eq!(chain.read_all().unwrap().len(), 0);
}

#[test]
fn payload_round_trips_through_json_serde() {
    let mut chain = OutcomeChain::new(InMemorySink::<OutcomePayload>::default(), NoSigning);
    let r = chain.append(tick("Applied", 0)).unwrap();
    let json = serde_json::to_string_pretty(&r).unwrap();
    let parsed: Receipt<OutcomePayload> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.sequence, r.sequence);
    assert_eq!(parsed.content_hash, r.content_hash);
    assert_eq!(parsed.payload.phase, "Applied");
}
