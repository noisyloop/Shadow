//! `shadow send <contact>` — open an interactive TUI session or send a single message

use anyhow::{anyhow, Result};

use crate::{
    store::{Store, Message},
    transport::nostr::{
        build_event_unsigned, decode_event_payload, RelayClient, DEFAULT_RELAY,
    },
    tui,
};

pub async fn run(contact_name: &str, message: Option<&str>, relay_url: Option<&str>) -> Result<()> {
    let store = Store::open()?;

    let contact = store
        .get_contact(contact_name)?
        .ok_or_else(|| anyhow!("Unknown contact '{}'. Use `shadow add` first.", contact_name))?;

    if let Some(msg) = message {
        // Non-interactive: send a single message via the Nostr relay and exit
        send_one(&store, &contact, msg, relay_url).await?;
    } else {
        // Interactive TUI session (relay not used in TUI mode)
        tui::run_session(store, contact).await?;
    }

    Ok(())
}

async fn send_one(
    store: &Store,
    contact: &crate::store::Contact,
    text: &str,
    relay_url: Option<&str>,
) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Require an existing ratchet session — we do not perform X3DH here.
    let session = store.load_session(contact)?;
    if session.is_none() {
        eprintln!(
            "No session with '{}'. Exchange keys first with `shadow add`.",
            contact.name
        );
        return Ok(());
    }
    let mut state = session.unwrap();

    let id_store = store.load_identity()?;
    let ad = derive_ad(&id_store.identity.ik_dh_pub, &contact.ik_dh_pub);

    let (_, _ct) = crate::crypto::ratchet::ratchet_encrypt(&mut state, text.as_bytes(), &ad)?;
    store.save_session(contact, &state)?;

    // ── Build and publish the Nostr event ─────────────────────────────── //

    let relay_url = relay_url.unwrap_or(DEFAULT_RELAY);

    // Use the contact's Nostr pubkey if available; fall back to Shadow IK DH pub.
    let recipient_nostr_pub: [u8; 32] = match &contact.nostr_pub {
        Some(hex) => {
            let bytes = hex::decode(hex)
                .map_err(|e| anyhow!("Invalid contact Nostr pubkey hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(anyhow!("Contact Nostr pubkey must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => contact.ik_dh_pub,
    };

    // Use our stored Nostr keypair if available; fall back to Shadow IK DH pub.
    let sender_nostr_pub: [u8; 32] = match &id_store.nostr_pub {
        Some(hex) => {
            let bytes = hex::decode(hex)
                .map_err(|e| anyhow!("Invalid local Nostr pubkey hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(anyhow!("Local Nostr pubkey must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => id_store.identity.ik_dh_pub,
    };

    // Build an unsigned event carrying the ciphertext as payload.
    // NOTE: Signing requires secp256k1 (Phase 4.1). For now we send the
    //       unsigned event; relay acceptance depends on the relay's policy.
    let event = build_event_unsigned(&sender_nostr_pub, &recipient_nostr_pub, &_ct);

    let relay = RelayClient::new(relay_url);
    relay.publish(&event).await
        .map_err(|e| anyhow!("Failed to publish to relay {relay_url}: {e}"))?;

    // ── Persist message locally ───────────────────────────────────────── //
    let msgs = store.load_messages(contact)?;
    let msg_id = msgs.len() as u64;
    store.append_message(contact, Message {
        id: msg_id,
        from_me: true,
        text: text.to_string(),
        timestamp: ts,
        delivered: true,
    })?;

    println!("Message sent via Nostr relay: {relay_url}");
    Ok(())
}

/// Derive session AD from both parties' identity keys (sorted for symmetry).
pub fn derive_ad(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
    let mut out = b"shadow-session-v1".to_vec();
    if a <= b {
        out.extend_from_slice(a);
        out.extend_from_slice(b);
    } else {
        out.extend_from_slice(b);
        out.extend_from_slice(a);
    }
    out
}
