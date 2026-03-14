//! `shadow add <name> <pubkey>` — add a contact by public key

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};

use crate::store::{Contact, Store};

pub fn run(name: &str, pubkey: &str, nostr_pub: Option<&str>) -> Result<()> {
    let store = Store::open()?;

    // Validate and decode the 64-char hex public key
    let raw = hex::decode(pubkey)
        .map_err(|_| anyhow!("pubkey must be 64 hex characters (32 bytes)"))?;
    if raw.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes (64 hex chars), got {}", raw.len()));
    }
    let mut ik_dh_pub = [0u8; 32];
    ik_dh_pub.copy_from_slice(&raw);

    if store.get_contact(name)?.is_some() {
        eprintln!("Contact '{}' already exists. Remove ~/.shadow/contacts.json to reset.", name);
        return Ok(());
    }

    let contact = Contact {
        name: name.to_string(),
        ik_dh_pub,
        nostr_pub: nostr_pub.map(str::to_string),
        added_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    };
    store.add_contact(contact)?;

    println!("Contact '{}' added.", name);
    println!("  Key: {}…{}", &pubkey[..8], &pubkey[pubkey.len()-8..]);

    Ok(())
}
