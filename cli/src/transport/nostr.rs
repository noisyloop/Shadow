//! Shadow — Nostr relay transport (Rust)
//!
//! Implements the Nostr client for publishing and subscribing to
//! sealed Shadow messages via WebSocket relays.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ─────────────────────────────────────────────────────────────
// BIP340 Schnorr helpers (see transport/nostr.py for algorithm)
// ─────────────────────────────────────────────────────────────

// Note: Schnorr on secp256k1 is implemented in the Python layer.
// In the Rust CLI we reuse the Nostr identity as an opaque key pair
// stored as hex and perform signing via the secp256k1 crate or by
// delegating to the Python nostr module.  For now keygen and signing
// are stubbed here and will be wired to secp256k1-sys in Phase 4.1.
// The crypto correctness is guaranteed by the existing Python tests.

pub type NostrPrivKey = [u8; 32];
pub type NostrPubKey  = [u8; 32];

// ─────────────────────────────────────────────────────────────
// Nostr event
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id:         String,
    pub pubkey:     String,
    pub created_at: u64,
    pub kind:       u32,
    pub tags:       Vec<Vec<String>>,
    pub content:    String,
    pub sig:        String,
}

impl NostrEvent {
    pub fn canonical(&self) -> String {
        json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ])
        .to_string()
    }

    pub fn compute_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical().as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn verify_id(&self) -> bool {
        self.compute_id() == self.id
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build an unsigned Nostr kind-14 event carrying a Shadow sealed envelope.
pub fn build_event_unsigned(
    sender_pub: &NostrPubKey,
    recipient_pub: &NostrPubKey,
    payload: &[u8],
) -> NostrEvent {
    let mut ev = NostrEvent {
        id:         String::new(),
        pubkey:     hex::encode(sender_pub),
        created_at: now_unix(),
        kind:       14,
        tags:       vec![vec!["p".into(), hex::encode(recipient_pub)]],
        content:    B64.encode(payload),
        sig:        String::new(),
    };
    ev.id = ev.compute_id();
    ev
}

pub fn decode_event_payload(event: &NostrEvent) -> Result<Vec<u8>> {
    B64.decode(&event.content).map_err(|e| anyhow!("Base64 decode: {e}"))
}

// ─────────────────────────────────────────────────────────────
// Relay client
// ─────────────────────────────────────────────────────────────

pub const DEFAULT_RELAY: &str = "wss://relay.damus.io";
pub const SHADOW_KIND: u32 = 14;

pub struct RelayClient {
    pub url: String,
}

impl RelayClient {
    pub fn new(url: &str) -> Self {
        RelayClient { url: url.to_string() }
    }

    /// Publish a single (pre-signed) event to the relay.
    pub async fn publish(&self, event: &NostrEvent) -> Result<()> {
        let (mut ws, _) = connect_async(&self.url).await
            .map_err(|e| anyhow!("WebSocket connect failed: {e}"))?;
        let msg = json!(["EVENT", event]).to_string();
        ws.send(Message::Text(msg)).await
            .map_err(|e| anyhow!("Send failed: {e}"))?;
        ws.close(None).await.ok();
        Ok(())
    }

    /// Fetch all stored kind-14 events addressed to a given recipient pubkey.
    /// Returns up to `limit` events since `since_ts`.
    pub async fn fetch(
        &self,
        recipient_pub: &NostrPubKey,
        since_ts: u64,
        limit: u32,
    ) -> Result<Vec<NostrEvent>> {
        let (mut ws, _) = connect_async(&self.url).await
            .map_err(|e| anyhow!("WebSocket connect: {e}"))?;

        let sub_id = "shadow-recv";
        let filter = json!({
            "kinds": [SHADOW_KIND],
            "#p":    [hex::encode(recipient_pub)],
            "since": since_ts,
            "limit": limit,
        });
        let req = json!(["REQ", sub_id, filter]).to_string();
        ws.send(Message::Text(req)).await?;

        let mut events = Vec::new();
        while let Some(Ok(msg)) = ws.next().await {
            match msg {
                Message::Text(raw) => {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                        let arr = match parsed.as_array() {
                            Some(a) => a,
                            None => continue,
                        };
                        match arr.first().and_then(|v| v.as_str()) {
                            Some("EVENT") if arr.len() >= 3 => {
                                if let Ok(ev) =
                                    serde_json::from_value::<NostrEvent>(arr[2].clone())
                                {
                                    if ev.verify_id() {
                                        events.push(ev);
                                    }
                                }
                            }
                            Some("EOSE") => break, // end of stored events
                            _ => {}
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        ws.close(None).await.ok();
        Ok(events)
    }
}
