//! `shadow recv` — poll for incoming messages

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::{
    store::Store,
    transport::nostr::{RelayClient, DEFAULT_RELAY, decode_event_payload},
};

pub async fn run(relay_url: Option<&str>) -> Result<()> {
    let store    = Store::open()?;
    let id_store = store.load_identity()?;

    let relay_url = relay_url.unwrap_or(DEFAULT_RELAY);
    let relay     = RelayClient::new(relay_url);

    println!("Polling {} for messages addressed to {}…",
        relay_url,
        &id_store.identity_pub_hex()[..16],
    );

    // Fetch events since 24h ago
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(86_400);

    // Note: Nostr pub key for routing is separate from Shadow identity key.
    // For now we use the Shadow IK DH pub bytes directly as the Nostr pub key.
    // Full integration would use a dedicated secp256k1 Nostr key pair.
    let mut nostr_pub = [0u8; 32];
    nostr_pub.copy_from_slice(&id_store.identity.ik_dh_pub);

    let events = match relay.fetch(&nostr_pub, since, 100).await {
        Ok(evs) => evs,
        Err(e) => {
            eprintln!("Relay fetch failed: {e}");
            eprintln!("(No network? Messages can still be exchanged via file: shadow send --file)");
            return Ok(());
        }
    };

    if events.is_empty() {
        println!("No new messages.");
        return Ok(());
    }

    let contacts = store.load_contacts()?;

    for event in &events {
        // Try to match envelope to a known contact by recipient hint
        match decode_event_payload(event) {
            Ok(payload) => {
                // Match sender Nostr pubkey to contact
                let sender_hex = &event.pubkey;
                let contact_name = contacts
                    .values()
                    .find(|c| c.nostr_pub.as_deref() == Some(sender_hex))
                    .map(|c| c.name.as_str())
                    .unwrap_or("unknown");

                println!(
                    "[{}] from {} ({} bytes)",
                    event.created_at,
                    contact_name,
                    payload.len()
                );
                println!("  → Use `shadow send {}` to open conversation", contact_name);
            }
            Err(e) => {
                eprintln!("Failed to decode event {}: {e}", &event.id[..8]);
            }
        }
    }

    println!("\n{} event(s) fetched.", events.len());
    Ok(())
}
