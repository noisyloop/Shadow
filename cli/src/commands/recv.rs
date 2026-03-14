//! `shadow recv` — poll for incoming messages from a Nostr relay

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::{
    store::{Message, Store},
    transport::nostr::{decode_event_payload, NostrEvent, RelayClient, DEFAULT_RELAY, SHADOW_KIND},
};

pub async fn run(relay_url: Option<&str>, timeout_secs: u64) -> Result<()> {
    let store    = Store::open()?;
    let id_store = store.load_identity()?;

    let relay_url = relay_url.unwrap_or(DEFAULT_RELAY);

    // Use our stored Nostr pubkey if available; fall back to Shadow IK DH pub.
    let mut nostr_pub = [0u8; 32];
    match &id_store.nostr_pub {
        Some(hex) => {
            let bytes = match hex::decode(hex) {
                Ok(b) if b.len() == 32 => b,
                Ok(_) => {
                    eprintln!("Stored Nostr pubkey has unexpected length; using Shadow IK DH pub.");
                    nostr_pub.copy_from_slice(&id_store.identity.ik_dh_pub);
                    vec![]
                }
                Err(e) => {
                    eprintln!("Stored Nostr pubkey is not valid hex ({e}); using Shadow IK DH pub.");
                    nostr_pub.copy_from_slice(&id_store.identity.ik_dh_pub);
                    vec![]
                }
            };
            if bytes.len() == 32 {
                nostr_pub.copy_from_slice(&bytes);
            }
        }
        None => {
            nostr_pub.copy_from_slice(&id_store.identity.ik_dh_pub);
        }
    }

    println!(
        "Connecting to {} …",
        relay_url,
    );
    println!(
        "Subscribing to kind-{} events for {} (timeout: {}s) …",
        SHADOW_KIND,
        &hex::encode(nostr_pub)[..16],
        timeout_secs,
    );

    // Fetch events since 24 h ago, up to 200 stored events.
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(86_400);

    let relay = RelayClient::new(relay_url);

    let events: Vec<NostrEvent> = match relay.fetch(&nostr_pub, since, 200).await {
        Ok(evs) => evs,
        Err(e) => {
            eprintln!("Connection to relay failed: {e}");
            eprintln!(
                "Check that the relay URL is reachable. \
                 Messages can be exchanged offline with `shadow send --file`."
            );
            return Ok(());
        }
    };

    if events.is_empty() {
        println!("No new messages.");
        return Ok(());
    }

    let contacts = store.load_contacts()?;
    let mut count = 0usize;

    for event in &events {
        match decode_event_payload(event) {
            Ok(payload) => {
                // Attempt to match sender Nostr pubkey to a known contact.
                let sender_hex   = &event.pubkey;
                let contact_opt  = contacts
                    .values()
                    .find(|c| c.nostr_pub.as_deref() == Some(sender_hex.as_str()));

                // Match envelope's recipient_key_hint against the local IK DH pub.
                // The hint is the first 8 bytes of the recipient IK DH pub (see sealed_sender.py).
                let hint_matches = if payload.len() >= 12 {
                    // Wire: hint_len(4) || hint_bytes || ...
                    let hint_len = u32::from_be_bytes(
                        payload[..4].try_into().unwrap_or([0; 4])
                    ) as usize;
                    if hint_len <= 8 && payload.len() >= 4 + hint_len {
                        let hint = &payload[4..4 + hint_len];
                        hint == &id_store.identity.ik_dh_pub[..hint_len]
                    } else {
                        true // cannot determine hint — assume it matches
                    }
                } else {
                    true
                };

                if !hint_matches {
                    // Not addressed to us — skip silently.
                    continue;
                }

                let contact_name = contact_opt
                    .map(|c| c.name.as_str())
                    .unwrap_or("unknown");

                println!(
                    "[{}] from {} ({} bytes payload)",
                    event.created_at,
                    contact_name,
                    payload.len(),
                );

                // If we know the contact, try to persist the raw event so the
                // TUI can decrypt and display it later.
                if let Some(contact) = contact_opt {
                    let ts = event.created_at as i64;
                    let msgs = store.load_messages(contact)?;
                    let msg_id = msgs.len() as u64;
                    // Store as a placeholder — full decryption requires the ratchet state
                    // and is performed by `shadow send <contact>` (TUI) or a future
                    // `shadow decrypt` command.
                    store.append_message(contact, Message {
                        id:        msg_id,
                        from_me:   false,
                        text:      format!("<encrypted — {} bytes>", payload.len()),
                        timestamp: ts,
                        delivered: false,
                    })?;
                }

                count += 1;
            }
            Err(e) => {
                eprintln!("Failed to decode event {}: {e}", &event.id[..8.min(event.id.len())]);
            }
        }
    }

    println!("\n{} message(s) received.", count);
    Ok(())
}
