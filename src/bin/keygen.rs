//! lava-outcome-chain-keygen — generate a fresh Ed25519 keypair for
//! lava-operator signing.
//!
//! Usage:
//!
//!     lava-outcome-chain-keygen
//!
//! Emits two lines on stdout:
//!
//!     SECRET <64-char hex>     # 32-byte secret seed (signer side)
//!     PUBLIC <64-char hex>     # 32-byte verifying key (verifier side)
//!
//! Hand the SECRET to the operator (typically via SOPS-encrypted
//! K8s Secret); hand the PUBLIC to verifiers (kensa / auditors).
//! The two strings are the entire keypair surface — no PEM, no
//! PKCS, no openssl dance.

fn main() {
    let signer = lava_outcome_chain::Ed25519Signer::generate();
    let secret = signer.secret_bytes();
    let public = signer.verifying_key().to_bytes();
    println!("SECRET {}", hex::encode(secret));
    println!("PUBLIC {}", hex::encode(public));
}
