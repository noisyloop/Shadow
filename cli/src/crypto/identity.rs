//! Shadow — Device Identity (Rust port)

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use super::ratchet::generate_dh;

// ─────────────────────────────────────────────────────────────
// DeviceIdentity
// ─────────────────────────────────────────────────────────────

/// Full device identity. All private key bytes stored as raw 32-byte arrays.
/// Signatures use Vec<u8> for serde compatibility (serde doesn't derive
/// Serialize/Deserialize for [u8; 64] by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// X25519 DH private key — used in X3DH DH operations.
    pub ik_dh_priv:   [u8; 32],
    /// X25519 DH public key.
    pub ik_dh_pub:    [u8; 32],
    /// ed25519 signing key seed (32 bytes).
    pub ik_sign_priv: [u8; 32],
    /// ed25519 verifying key (32 bytes).
    pub ik_sign_pub:  [u8; 32],
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let (ik_dh_priv, ik_dh_pub) = generate_dh();
        let signing_key = SigningKey::generate(&mut OsRng);
        let ik_sign_priv: [u8; 32] = signing_key.to_bytes();
        let ik_sign_pub:  [u8; 32] = signing_key.verifying_key().to_bytes();
        DeviceIdentity { ik_dh_priv, ik_dh_pub, ik_sign_priv, ik_sign_pub }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let key = SigningKey::from_bytes(&self.ik_sign_priv);
        let sig: Signature = key.sign(data);
        sig.to_bytes().to_vec()
    }
}

// ─────────────────────────────────────────────────────────────
// Pre-keys
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id:        u32,
    pub priv_key:  [u8; 32],
    pub pub_key:   [u8; 32],
    /// ed25519 signature of pub_key (64 bytes, stored as Vec<u8>)
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id:       u32,
    pub priv_key: [u8; 32],
    pub pub_key:  [u8; 32],
}

impl DeviceIdentity {
    pub fn generate_spk(&self, id: u32) -> SignedPreKey {
        let (priv_key, pub_key) = generate_dh();
        let signature = self.sign(&pub_key);
        SignedPreKey { id, priv_key, pub_key, signature }
    }

    pub fn generate_opks(&self, count: u32, start_id: u32) -> Vec<OneTimePreKey> {
        (0..count)
            .map(|i| {
                let (priv_key, pub_key) = generate_dh();
                OneTimePreKey { id: start_id + i, priv_key, pub_key }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────
// PreKeyBundle — public half published to the server
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key:      [u8; 32],
    pub identity_sign_key: [u8; 32],
    pub spk_id:            u32,
    pub spk_public:        [u8; 32],
    /// ed25519 signature (64 bytes as Vec<u8>)
    pub spk_signature:     Vec<u8>,
    pub opk_id:            Option<u32>,
    pub opk_public:        Option<[u8; 32]>,
}

impl DeviceIdentity {
    pub fn build_bundle(&self, spk: &SignedPreKey, opk: Option<&OneTimePreKey>) -> PreKeyBundle {
        PreKeyBundle {
            identity_key:      self.ik_dh_pub,
            identity_sign_key: self.ik_sign_pub,
            spk_id:            spk.id,
            spk_public:        spk.pub_key,
            spk_signature:     spk.signature.clone(),
            opk_id:            opk.map(|o| o.id),
            opk_public:        opk.map(|o| o.pub_key),
        }
    }
}

/// Verify the SPK signature in a bundle. Returns Err on failure.
pub fn verify_bundle(bundle: &PreKeyBundle) -> Result<()> {
    if bundle.spk_signature.len() != 64 {
        return Err(anyhow::anyhow!("SPK signature wrong length"));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&bundle.spk_signature);
    let vk = VerifyingKey::from_bytes(&bundle.identity_sign_key)
        .map_err(|e| anyhow::anyhow!("Bad verify key: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&bundle.spk_public, &sig)
        .map_err(|_| anyhow::anyhow!("SPK signature verification failed"))
}
