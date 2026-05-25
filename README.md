# lava-outcome-chain

Typed BLAKE3-linked `OutcomeChain<P: Payload>` for IaC reconcile-tick
attestation. First foundation crate of the lava-suite (L1).

## Shape

```text
Receipt<P>₀ ──prev_hash──▶ Receipt<P>₁ ──prev_hash──▶ Receipt<P>₂
  ─ sequence: 0              ─ sequence: 1              ─ sequence: 2
  ─ prev: ZERO               ─ prev: H(₀)               ─ prev: H(₁)
  ─ payload (typed P)        ─ payload (typed P)        ─ payload (P)
  ─ content_hash (BLAKE3)    ─ content_hash             ─ content_hash
  ─ signature (optional)     ─ signature                ─ signature
```

## Abstractions

| Trait | Impls shipped | Purpose |
|---|---|---|
| `Payload` | `OutcomePayload` | Per-controller receipt body |
| `OutcomeSink<P>` | `InMemorySink`, `FilesystemSink`, `NullSink` | Persistence |
| `SigningProvider` | `NoSigning`, `Ed25519Signer` | Attestation |
| `SignatureVerifier` | `NoOpVerifier`, `Ed25519Verifier` | Validation |

## Verify

`verify_chain(receipts, &verifier)` walks the chain and proves:

1. Sequence numbers monotonic from 0.
2. Genesis receipt's `prev_hash` is the all-zero sentinel.
3. Each receipt's `prev_hash` matches the previous's `content_hash`.
4. Each receipt's `content_hash` matches a fresh re-hash (no tampering).
5. Each receipt's signature validates under the supplied verifier.
6. Timestamps are monotonic.

First failure surfaces as a typed `VerifyError` naming the receipt
and invariant.

## Use

```rust
let signer = Ed25519Signer::generate();
let verifier = Ed25519Verifier::new(signer.verifying_key());
let sink = FilesystemSink::<OutcomePayload>::new("/var/lib/lava", "rio-infra-prod")?;
let mut chain = OutcomeChain::new(sink, signer);

chain.append(OutcomePayload {
    resource: ResourceAddress::new("rio", "infra", "prod-vpc"),
    spec_hash: ContentHash::of(spec_bytes),
    terraform_json_hash: ContentHash::of(tf_json_bytes),
    plan_id: Some("plan-1".into()),
    phase: "Applied".into(),
    ..Default::default()
})?;

verify_chain(&chain.read_all()?, &verifier)?;
```

## Tests

36 tests pass: 32 unit + 4 integration covering 5-tick chain
verification, filesystem round-trip with Ed25519, NullSink semantics,
and JSON serde round-trip of receipts.
