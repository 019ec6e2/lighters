//! Ethereum L1 signing (`eth` feature).
//!
//! Some transactions (`Transfer`, `ChangePubKey`, `ApproveIntegrator`) carry an
//! additional `L1Sig`: an Ethereum `personal_sign` (EIP-191) signature by the
//! account's L1 wallet over the human-readable `message_to_sign`. This module
//! reproduces `eth_account.Account.sign_message(encode_defunct(text=msg))`.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::error::{Error, Result};

/// An Ethereum (secp256k1) signer used to produce L1 `personal_sign` signatures.
#[derive(Clone)]
pub struct EthSigner {
    key: SigningKey,
}

impl EthSigner {
    /// Builds a signer from a 32-byte hex private key (optionally `0x`-prefixed).
    pub fn from_hex(private_key: &str) -> Result<Self> {
        let bytes = hex::decode(private_key.trim_start_matches("0x"))?;
        let key = SigningKey::from_slice(&bytes).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(EthSigner { key })
    }

    /// The 20-byte checksummed-lowercase Ethereum address, `0x`-prefixed.
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(address_of(self.key.verifying_key())))
    }

    /// Signs `message` with EIP-191 `personal_sign` and returns the 65-byte
    /// signature as `0x` + `r || s || v` (v ∈ {27, 28}).
    pub fn sign_eip191(&self, message: &str) -> Result<String> {
        let hash = eip191_hash(message.as_bytes());
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut out = sig.to_bytes().to_vec(); // 64 bytes: r || s (low-S normalized)
        out.push(27 + recid.to_byte());
        Ok(format!("0x{}", hex::encode(out)))
    }
}

/// EIP-191 `personal_sign` digest: `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`.
fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Derives the 20-byte address from a public key: `keccak256(uncompressed[1..])[12..]`.
fn address_of(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Recovers the signer address from an EIP-191 signature over `message`.
///
/// Useful for verifying a produced signature round-trips to the expected wallet.
pub fn recover_eip191(message: &str, signature_hex: &str) -> Result<String> {
    let raw = hex::decode(signature_hex.trim_start_matches("0x"))?;
    if raw.len() != 65 {
        return Err(Error::Crypto(format!(
            "expected 65-byte signature, got {}",
            raw.len()
        )));
    }
    let recid = RecoveryId::from_byte(raw[64].wrapping_sub(27))
        .ok_or_else(|| Error::Crypto("invalid recovery id".to_string()))?;
    let sig = Signature::from_slice(&raw[..64]).map_err(|e| Error::Crypto(e.to_string()))?;
    let hash = eip191_hash(message.as_bytes());
    let vk = VerifyingKey::recover_from_prehash(&hash, &sig, recid)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(address_of(&vk))))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hardhat/anvil well-known account #0.
    const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    #[test]
    fn address_matches_known_account() {
        let signer = EthSigner::from_hex(KEY).unwrap();
        assert_eq!(signer.address(), ADDR);
    }

    #[test]
    fn signature_recovers_to_signer() {
        let signer = EthSigner::from_hex(KEY).unwrap();
        let msg = "Register Lighter Account\n\npubkey: 0x00";
        let sig = signer.sign_eip191(msg).unwrap();
        assert!(sig.starts_with("0x"));
        // 0x + 130 hex chars = 65 bytes.
        assert_eq!(sig.len(), 2 + 130);
        assert_eq!(recover_eip191(msg, &sig).unwrap(), ADDR);
    }
}
