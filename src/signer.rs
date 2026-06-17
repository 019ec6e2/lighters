//! API-key management and Schnorr signing.
//!
//! All cryptography is delegated to the [`goldilocks-crypto`] crate, which
//! provides an ECgFp5 + Schnorr implementation byte-compatible with the Go
//! reference (`poseidon_crypto`). This module only adapts it to the Lighter
//! signer interface.

use goldilocks_crypto::Point;
use goldilocks_crypto::{sign_hashed_message, verify_signature, ScalarField};

use crate::constants::{PRIVATE_KEY_LENGTH, PUB_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::error::{Error, Result};

/// An API key: a private scalar plus cached 40-byte little-endian encodings of
/// the private and public keys.
#[derive(Clone)]
pub struct KeyManager {
    scalar: ScalarField,
    private_key: [u8; PRIVATE_KEY_LENGTH],
    public_key: [u8; PUB_KEY_LENGTH],
}

impl KeyManager {
    /// Builds a key manager from 40 little-endian private-key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATE_KEY_LENGTH {
            return Err(Error::InvalidPrivateKeyLength(bytes.len()));
        }
        let scalar = ScalarField::from_bytes_le(bytes).map_err(Error::Crypto)?;
        let mut private_key = [0u8; PRIVATE_KEY_LENGTH];
        private_key.copy_from_slice(bytes);
        let public_key = Self::derive_public_key(&scalar);
        Ok(KeyManager {
            scalar,
            private_key,
            public_key,
        })
    }

    /// Parses a hex-encoded (optionally `0x`-prefixed) 40-byte private key.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Generates a fresh, cryptographically random API key.
    pub fn generate() -> Self {
        let scalar = ScalarField::sample_crypto();
        let private_key = scalar.to_bytes_le();
        let public_key = Self::derive_public_key(&scalar);
        KeyManager {
            scalar,
            private_key,
            public_key,
        }
    }

    fn derive_public_key(scalar: &ScalarField) -> [u8; PUB_KEY_LENGTH] {
        // pk = (sk · G).encode(), matching Go's SchnorrPkFromSk.
        let encoded = Point::generator().mul(scalar).encode().to_bytes_le();
        let mut pk = [0u8; PUB_KEY_LENGTH];
        pk.copy_from_slice(&encoded);
        pk
    }

    /// The 40-byte little-endian private key.
    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.private_key
    }

    /// The 40-byte little-endian public key (encoded curve point).
    pub fn public_key_bytes(&self) -> [u8; PUB_KEY_LENGTH] {
        self.public_key
    }

    /// `0x`-prefixed hex private key (as returned by `GenerateAPIKey`).
    pub fn private_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.private_key))
    }

    /// `0x`-prefixed hex public key.
    pub fn public_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.public_key))
    }

    /// Signs a 40-byte message hash with a freshly sampled nonce.
    ///
    /// Equivalent to Go's `keyManager.Sign` → `SchnorrSignHashedMessage`.
    pub fn sign(&self, message_hash: &[u8]) -> Result<[u8; SIGNATURE_LENGTH]> {
        let nonce = ScalarField::sample_crypto().to_bytes_le();
        self.sign_with_nonce(message_hash, &nonce)
    }

    /// Signs a 40-byte message hash with an explicit nonce (deterministic).
    ///
    /// Mainly useful for reproducible test vectors; mirrors
    /// `SchnorrSignHashedMessage2`.
    pub fn sign_with_nonce(
        &self,
        message_hash: &[u8],
        nonce: &[u8],
    ) -> Result<[u8; SIGNATURE_LENGTH]> {
        let sig = sign_hashed_message(&self.private_key, message_hash, nonce)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        sig.try_into()
            .map_err(|_| Error::InvalidSignature)
    }

    /// Verifies a signature over `message_hash` against this key's public key.
    pub fn verify(&self, message_hash: &[u8], signature: &[u8]) -> bool {
        verify_signature(signature, message_hash, &self.public_key).unwrap_or(false)
    }

    /// The underlying scalar (rarely needed directly).
    pub fn scalar(&self) -> &ScalarField {
        &self.scalar
    }
}

/// Verifies a Schnorr signature against an arbitrary 40-byte public key.
pub fn verify(message_hash: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    verify_signature(signature, message_hash, public_key).unwrap_or(false)
}

impl std::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material.
        f.debug_struct("KeyManager")
            .field("public_key", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}
