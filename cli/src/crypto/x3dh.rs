//! Shadow — X3DH Handshake (Rust port)
//! Reference: https://signal.org/docs/specifications/x3dh/

use anyhow::Result;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::{
    identity::{DeviceIdentity, OneTimePreKey, PreKeyBundle, SignedPreKey, verify_bundle},
    ratchet::{
        dh, ratchet_decrypt, ratchet_encrypt, ratchet_init_alice, ratchet_init_bob,
        Header, RatchetState,
    },
};

const X3DH_F:    &[u8] = &[0xff; 32];
const X3DH_INFO: &[u8] = b"ShadowX3DH";
const X3DH_SALT: &[u8] = &[0x00; 32];

// ─────────────────────────────────────────────────────────────
// KDF
// ─────────────────────────────────────────────────────────────

fn kdf_x3dh(dh_outputs: &[[u8; 32]]) -> [u8; 32] {
    let mut ikm = X3DH_F.to_vec();
    for d in dh_outputs {
        ikm.extend_from_slice(d);
    }
    let hk = Hkdf::<Sha256>::new(Some(X3DH_SALT), &ikm);
    let mut sk = [0u8; 32];
    hk.expand(X3DH_INFO, &mut sk).expect("HKDF expand");
    sk
}

// ─────────────────────────────────────────────────────────────
// Wire format
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    pub ik_pub:       [u8; 32],
    pub ek_pub:       [u8; 32],
    pub spk_id:       u32,
    pub opk_id:       Option<u32>,
    pub header_bytes: Vec<u8>,
    pub ciphertext:   Vec<u8>,
}

// ─────────────────────────────────────────────────────────────
// Sender (Alice)
// ─────────────────────────────────────────────────────────────

pub fn x3dh_send(
    alice:      &DeviceIdentity,
    bob_bundle: &PreKeyBundle,
    plaintext:  &[u8],
    ad:         &[u8],
) -> Result<(InitialMessage, RatchetState)> {
    verify_bundle(bob_bundle)?;

    let (ek_priv, ek_pub) = super::ratchet::generate_dh();

    let dh1 = dh(&alice.ik_dh_priv, &bob_bundle.spk_public);
    let dh2 = dh(&ek_priv,          &bob_bundle.identity_key);
    let dh3 = dh(&ek_priv,          &bob_bundle.spk_public);
    let mut outputs = vec![dh1, dh2, dh3];

    if let Some(opk_pub) = bob_bundle.opk_public {
        outputs.push(dh(&ek_priv, &opk_pub));
    }

    let sk = kdf_x3dh(&outputs);
    let mut alice_state = ratchet_init_alice(&sk, &bob_bundle.spk_public);
    let (header, ct) = ratchet_encrypt(&mut alice_state, plaintext, ad)?;

    Ok((
        InitialMessage {
            ik_pub: alice.ik_dh_pub,
            ek_pub,
            spk_id: bob_bundle.spk_id,
            opk_id: bob_bundle.opk_id,
            header_bytes: header.serialize(),
            ciphertext: ct,
        },
        alice_state,
    ))
}

// ─────────────────────────────────────────────────────────────
// Receiver (Bob)
// ─────────────────────────────────────────────────────────────

pub fn x3dh_receive(
    bob:  &DeviceIdentity,
    spk:  &SignedPreKey,
    opk:  Option<&OneTimePreKey>,
    msg:  &InitialMessage,
    ad:   &[u8],
) -> Result<(Vec<u8>, RatchetState)> {
    let dh1 = dh(&spk.priv_key,    &msg.ik_pub);
    let dh2 = dh(&bob.ik_dh_priv,  &msg.ek_pub);
    let dh3 = dh(&spk.priv_key,    &msg.ek_pub);
    let mut outputs = vec![dh1, dh2, dh3];

    if let Some(o) = opk {
        outputs.push(dh(&o.priv_key, &msg.ek_pub));
    }

    let sk = kdf_x3dh(&outputs);
    let mut bob_state = ratchet_init_bob(&sk, &spk.priv_key, &spk.pub_key);
    let header = Header::deserialize(&msg.header_bytes)?;
    let plaintext = ratchet_decrypt(&mut bob_state, &header, &msg.ciphertext, ad)?;

    Ok((plaintext, bob_state))
}
