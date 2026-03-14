//! Shadow — Double Ratchet Protocol (Rust port)
//! Reference: https://signal.org/docs/specifications/doubleratchet/
//!
//! Primitives: X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA256

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const MAX_SKIP: u32 = 1000;
const HKDF_INFO_RK: &[u8] = b"ShadowRootKey";
const HMAC_CK_CONST: &[u8] = &[0x01];
const HMAC_MK_CONST: &[u8] = &[0x02];

// ─────────────────────────────────────────────────────────────
// DH helpers
// ─────────────────────────────────────────────────────────────

/// Generate a fresh X25519 keypair. Returns (priv_bytes, pub_bytes).
pub fn generate_dh() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

/// X25519 Diffie-Hellman.
pub fn dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv_bytes);
    let public = PublicKey::from(*pub_bytes);
    secret.diffie_hellman(&public).to_bytes()
}

// ─────────────────────────────────────────────────────────────
// KDF functions
// ─────────────────────────────────────────────────────────────

/// KDF_RK(rk, dh_out) → (new_rk, ck)  — HKDF-SHA256.
pub fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key.as_ref()), dh_out.as_ref());
    let mut okm = [0u8; 64];
    hk.expand(HKDF_INFO_RK, &mut okm)
        .expect("HKDF expand failed");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    (rk, ck)
}

/// KDF_CK(ck) → (new_ck, mk)  — HMAC-SHA256 with 0x01 / 0x02 constants.
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac_ck = <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key size");
    mac_ck.update(HMAC_CK_CONST);
    let new_ck_bytes = mac_ck.finalize().into_bytes();

    let mut mac_mk = <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key size");
    mac_mk.update(HMAC_MK_CONST);
    let mk_bytes = mac_mk.finalize().into_bytes();

    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    new_ck.copy_from_slice(&new_ck_bytes);
    mk.copy_from_slice(&mk_bytes);
    (new_ck, mk)
}

// ─────────────────────────────────────────────────────────────
// AEAD: AES-256-GCM
// ─────────────────────────────────────────────────────────────

pub fn aead_encrypt(
    message_key: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ct = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: associated_data })
        .expect("AES-GCM encrypt");
    let mut out = nonce_bytes.to_vec();
    out.append(&mut ct);
    out
}

pub fn aead_decrypt(
    message_key: &[u8; 32],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(anyhow!("Ciphertext too short"));
    }
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let key = Key::<Aes256Gcm>::from_slice(message_key);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: &ciphertext[12..], aad: associated_data })
        .map_err(|_| anyhow!("AES-GCM decryption failed"))
}

// ─────────────────────────────────────────────────────────────
// Message header
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n:  u32,
}

impl Header {
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = self.dh.to_vec();
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 40 {
            return Err(anyhow!("Header too short"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&data[..32]);
        let pn = u32::from_be_bytes(data[32..36].try_into()?);
        let n  = u32::from_be_bytes(data[36..40].try_into()?);
        Ok(Header { dh, pn, n })
    }
}

/// Build the authenticated associated data: outer AD || header_length || header.
pub fn concat_ad(ad: &[u8], header: &Header) -> Vec<u8> {
    let hdr = header.serialize();
    let mut out = ad.to_vec();
    out.extend_from_slice(&(hdr.len() as u32).to_be_bytes());
    out.extend_from_slice(&hdr);
    out
}

// ─────────────────────────────────────────────────────────────
// Ratchet state
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetState {
    pub dhs_priv: [u8; 32],
    pub dhs_pub:  [u8; 32],
    pub dhr:      Option<[u8; 32]>,
    pub rk:       [u8; 32],
    pub cks:      Option<[u8; 32]>,
    pub ckr:      Option<[u8; 32]>,
    pub ns:       u32,
    pub nr:       u32,
    pub pn:       u32,
    // key = "{dh_pub_hex}:{n}"
    pub mk_skipped: HashMap<String, [u8; 32]>,
}

fn skipped_key(dh_pub: &[u8; 32], n: u32) -> String {
    format!("{}:{}", hex::encode(dh_pub), n)
}

// ─────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────

pub fn ratchet_init_alice(sk: &[u8; 32], bob_dh_pub: &[u8; 32]) -> RatchetState {
    let (dhs_priv, dhs_pub) = generate_dh();
    let dh_out = dh(&dhs_priv, bob_dh_pub);
    let (rk, cks) = kdf_rk(sk, &dh_out);
    RatchetState {
        dhs_priv,
        dhs_pub,
        dhr: Some(*bob_dh_pub),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0, nr: 0, pn: 0,
        mk_skipped: HashMap::new(),
    }
}

pub fn ratchet_init_bob(sk: &[u8; 32], spk_priv: &[u8; 32], spk_pub: &[u8; 32]) -> RatchetState {
    RatchetState {
        dhs_priv: *spk_priv,
        dhs_pub:  *spk_pub,
        dhr: None,
        rk:  *sk,
        cks: None,
        ckr: None,
        ns: 0, nr: 0, pn: 0,
        mk_skipped: HashMap::new(),
    }
}

// ─────────────────────────────────────────────────────────────
// Encrypt / Decrypt
// ─────────────────────────────────────────────────────────────

pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    ad: &[u8],
) -> Result<(Header, Vec<u8>)> {
    let ck = state.cks.ok_or_else(|| anyhow!("No sending chain key"))?;
    let (new_ck, mk) = kdf_ck(&ck);
    state.cks = Some(new_ck);

    let header = Header { dh: state.dhs_pub, pn: state.pn, n: state.ns };
    state.ns += 1;

    let aad = concat_ad(ad, &header);
    let ct = aead_encrypt(&mk, plaintext, &aad);
    Ok((header, ct))
}

fn try_skipped(
    state: &mut RatchetState,
    header: &Header,
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Option<Vec<u8>>> {
    let k = skipped_key(&header.dh, header.n);
    if let Some(mk) = state.mk_skipped.remove(&k) {
        let aad = concat_ad(ad, header);
        return Ok(Some(aead_decrypt(&mk, ciphertext, &aad)?));
    }
    Ok(None)
}

fn skip_keys(state: &mut RatchetState, until: u32) -> Result<()> {
    if state.nr + MAX_SKIP < until {
        return Err(anyhow!("Too many skipped messages"));
    }
    while state.nr < until {
        if let Some(ck) = state.ckr {
            let (new_ck, mk) = kdf_ck(&ck);
            state.ckr = Some(new_ck);
            let dhr = state.dhr.ok_or_else(|| anyhow!("No DHr"))?;
            state.mk_skipped.insert(skipped_key(&dhr, state.nr), mk);
            state.nr += 1;
        } else {
            break;
        }
    }
    Ok(())
}

fn dh_ratchet(state: &mut RatchetState, header: &Header) {
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.dhr = Some(header.dh);

    let dh1 = dh(&state.dhs_priv, &header.dh);
    let (rk1, ckr) = kdf_rk(&state.rk, &dh1);
    state.rk  = rk1;
    state.ckr = Some(ckr);

    let (new_priv, new_pub) = generate_dh();
    state.dhs_priv = new_priv;
    state.dhs_pub  = new_pub;

    let dh2 = dh(&state.dhs_priv, &header.dh);
    let (rk2, cks) = kdf_rk(&state.rk, &dh2);
    state.rk  = rk2;
    state.cks = Some(cks);
}

pub fn ratchet_decrypt(
    state: &mut RatchetState,
    header: &Header,
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Check skipped keys first
    if let Some(pt) = try_skipped(state, header, ciphertext, ad)? {
        return Ok(pt);
    }

    // DH ratchet if sender key has changed
    let need_ratchet = match state.dhr {
        Some(ref dhr) => dhr != &header.dh,
        None => true,
    };
    if need_ratchet {
        skip_keys(state, header.pn)?;
        dh_ratchet(state, header);
    }

    skip_keys(state, header.n)?;

    let ck = state.ckr.ok_or_else(|| anyhow!("No receiving chain key"))?;
    let (new_ck, mk) = kdf_ck(&ck);
    state.ckr = Some(new_ck);
    state.nr += 1;

    let aad = concat_ad(ad, header);
    aead_decrypt(&mk, ciphertext, &aad)
}
