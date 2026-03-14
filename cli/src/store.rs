//! Shadow — Local persistent store
//!
//! Layout: ~/.shadow/
//!   identity.json      — device keypair + current SPK + OPK pool
//!   contacts.json      — name → {ik_dh_pub, nostr_pub}
//!   sessions/<hex>.json — per-contact RatchetState
//!   messages/<hex>.json — per-contact message log

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    identity::{DeviceIdentity, OneTimePreKey, SignedPreKey},
    ratchet::RatchetState,
};

// ─────────────────────────────────────────────────────────────
// Shadow home directory
// ─────────────────────────────────────────────────────────────

pub fn shadow_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".shadow")
}

fn ensure_dirs(base: &Path) -> Result<()> {
    fs::create_dir_all(base.join("sessions"))?;
    fs::create_dir_all(base.join("messages"))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Identity store
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStore {
    pub identity: DeviceIdentity,
    pub spk:      SignedPreKey,
    pub spk_gen:  u32,                   // SPK generation counter
    pub opks:     Vec<OneTimePreKey>,    // unspent OPK pool
    pub opk_counter: u32,
    /// Optional secp256k1 Nostr key (hex) for relay publishing
    pub nostr_priv: Option<String>,
    pub nostr_pub:  Option<String>,
}

impl IdentityStore {
    pub fn new() -> Self {
        let identity = DeviceIdentity::generate();
        let spk = identity.generate_spk(0);
        let opks = identity.generate_opks(10, 0);
        IdentityStore {
            identity,
            spk,
            spk_gen: 0,
            opk_counter: 10,
            opks,
            nostr_priv: None,
            nostr_pub: None,
        }
    }

    pub fn identity_pub_hex(&self) -> String {
        hex::encode(self.identity.ik_dh_pub)
    }

    pub fn rotate_spk(&mut self) {
        self.spk_gen += 1;
        self.spk = self.identity.generate_spk(self.spk_gen);
    }

    pub fn replenish_opks(&mut self, count: u32) -> Vec<OneTimePreKey> {
        let new_opks = self.identity.generate_opks(count, self.opk_counter);
        self.opk_counter += count;
        self.opks.extend(new_opks.iter().cloned());
        new_opks
    }

    pub fn pop_opk(&mut self) -> Option<OneTimePreKey> {
        if self.opks.is_empty() {
            None
        } else {
            Some(self.opks.remove(0))
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Contact
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name:        String,
    pub ik_dh_pub:   [u8; 32],
    pub nostr_pub:   Option<String>,
    pub added_at:    i64,
}

impl Contact {
    pub fn pub_hex(&self) -> String {
        hex::encode(self.ik_dh_pub)
    }

    /// Short display ID (first 8 chars of hex key).
    pub fn short_id(&self) -> String {
        hex::encode(&self.ik_dh_pub[..4])
    }

    fn session_key(&self) -> String {
        hex::encode(&self.ik_dh_pub[..16])
    }
}

// ─────────────────────────────────────────────────────────────
// Message log
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id:        u64,
    pub from_me:   bool,
    pub text:      String,
    pub timestamp: i64,
    pub delivered: bool,
}

// ─────────────────────────────────────────────────────────────
// Store — top-level API
// ─────────────────────────────────────────────────────────────

pub struct Store {
    base: PathBuf,
}

impl Store {
    pub fn open() -> Result<Self> {
        let base = shadow_dir();
        ensure_dirs(&base)?;
        Ok(Store { base })
    }

    pub fn is_initialised(&self) -> bool {
        self.base.join("identity.json").exists()
    }

    // ── Identity ────────────────────────────────────────────

    pub fn save_identity(&self, id_store: &IdentityStore) -> Result<()> {
        let path = self.base.join("identity.json");
        let json = serde_json::to_string_pretty(id_store)?;
        fs::write(&path, json).context("write identity.json")?;
        Ok(())
    }

    pub fn load_identity(&self) -> Result<IdentityStore> {
        let path = self.base.join("identity.json");
        let json = fs::read_to_string(&path).context("read identity.json — run `shadow init` first")?;
        Ok(serde_json::from_str(&json)?)
    }

    // ── Contacts ────────────────────────────────────────────

    pub fn load_contacts(&self) -> Result<HashMap<String, Contact>> {
        let path = self.base.join("contacts.json");
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn save_contacts(&self, contacts: &HashMap<String, Contact>) -> Result<()> {
        let json = serde_json::to_string_pretty(contacts)?;
        fs::write(self.base.join("contacts.json"), json)?;
        Ok(())
    }

    pub fn get_contact(&self, name: &str) -> Result<Option<Contact>> {
        Ok(self.load_contacts()?.remove(name))
    }

    pub fn add_contact(&self, contact: Contact) -> Result<()> {
        let mut contacts = self.load_contacts()?;
        contacts.insert(contact.name.clone(), contact);
        self.save_contacts(&contacts)
    }

    // ── Sessions ────────────────────────────────────────────

    fn session_path(&self, contact: &Contact) -> PathBuf {
        self.base.join("sessions").join(format!("{}.json", contact.session_key()))
    }

    pub fn load_session(&self, contact: &Contact) -> Result<Option<RatchetState>> {
        let path = self.session_path(contact);
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&json)?))
    }

    pub fn save_session(&self, contact: &Contact, state: &RatchetState) -> Result<()> {
        let json = serde_json::to_string(state)?;
        fs::write(self.session_path(contact), json)?;
        Ok(())
    }

    // ── Messages ────────────────────────────────────────────

    fn messages_path(&self, contact: &Contact) -> PathBuf {
        self.base.join("messages").join(format!("{}.json", contact.session_key()))
    }

    pub fn load_messages(&self, contact: &Contact) -> Result<Vec<Message>> {
        let path = self.messages_path(contact);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn append_message(&self, contact: &Contact, msg: Message) -> Result<()> {
        let mut msgs = self.load_messages(contact)?;
        msgs.push(msg);
        let json = serde_json::to_string(&msgs)?;
        fs::write(self.messages_path(contact), json)?;
        Ok(())
    }
}
