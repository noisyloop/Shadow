//! `shadow send <contact>` — open an interactive TUI session

use anyhow::{anyhow, Result};

use crate::{store::Store, tui};

pub async fn run(contact_name: &str, message: Option<&str>) -> Result<()> {
    let store = Store::open()?;

    let contact = store
        .get_contact(contact_name)?
        .ok_or_else(|| anyhow!("Unknown contact '{}'. Use `shadow add` first.", contact_name))?;

    if let Some(msg) = message {
        // Non-interactive: send a single message and exit
        send_one(&store, &contact, msg)?;
    } else {
        // Interactive TUI session
        tui::run_session(store, contact).await?;
    }

    Ok(())
}

fn send_one(
    store: &Store,
    contact: &crate::store::Contact,
    text: &str,
) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::store::Message;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Load or create ratchet session
    let session = store.load_session(contact)?;
    if session.is_none() {
        eprintln!(
            "No active session with '{}'. \
             Exchange keys first via X3DH (prekey bundle import).",
            contact.name
        );
        return Ok(());
    }
    let mut state = session.unwrap();

    let id_store = store.load_identity()?;
    let ad = derive_ad(&id_store.identity.ik_dh_pub, &contact.ik_dh_pub);

    let (_, _ct) = crate::crypto::ratchet::ratchet_encrypt(&mut state, text.as_bytes(), &ad)?;
    store.save_session(contact, &state)?;

    let msgs = store.load_messages(contact)?;
    let msg_id = msgs.len() as u64;
    store.append_message(contact, Message {
        id: msg_id,
        from_me: true,
        text: text.to_string(),
        timestamp: ts,
        delivered: false,
    })?;

    println!("Message queued for '{}'. Use `shadow recv` to deliver.", contact.name);
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
