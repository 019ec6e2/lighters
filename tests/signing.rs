//! Validates the Schnorr signer against a deterministic Go vector
//! (`lighter-go/cmd/sigvector`): public-key derivation and a fixed-nonce
//! signature must match byte-for-byte, and freshly produced signatures must
//! verify.

use lighter::signer::{self, KeyManager};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SigVector {
    priv_key: String,
    pub_key: String,
    msg_hash: String,
    nonce: String,
    sig: String,
}

fn load() -> SigVector {
    serde_json::from_str(include_str!("sigvector.json")).expect("parse sigvector.json")
}

#[test]
fn pubkey_derivation_matches_go() {
    let v = load();
    let km = KeyManager::from_hex(&v.priv_key).unwrap();
    assert_eq!(hex::encode(km.public_key_bytes()), v.pub_key);
}

#[test]
fn deterministic_signature_matches_go() {
    let v = load();
    let km = KeyManager::from_hex(&v.priv_key).unwrap();
    let msg = hex::decode(&v.msg_hash).unwrap();
    let nonce = hex::decode(&v.nonce).unwrap();
    let sig = km.sign_with_nonce(&msg, &nonce).unwrap();
    assert_eq!(hex::encode(sig), v.sig, "signature mismatch with Go");
}

#[test]
fn random_signature_verifies() {
    let v = load();
    let km = KeyManager::from_hex(&v.priv_key).unwrap();
    let msg = hex::decode(&v.msg_hash).unwrap();
    let sig = km.sign(&msg).unwrap();
    assert!(km.verify(&msg, &sig), "self-verify failed");
    assert!(
        signer::verify(&msg, &sig, &km.public_key_bytes()),
        "standalone verify failed"
    );
}

#[test]
fn generated_key_roundtrips() {
    let km = KeyManager::generate();
    let msg = [3u8; 40];
    let sig = km.sign(&msg).unwrap();
    assert!(km.verify(&msg, &sig));
}
