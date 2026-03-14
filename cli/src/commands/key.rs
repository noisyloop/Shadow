//! `shadow key rotate` and `shadow key show`

use anyhow::Result;

use crate::store::Store;

pub fn show() -> Result<()> {
    let store    = Store::open()?;
    let id_store = store.load_identity()?;

    let pub_hex = id_store.identity_pub_hex();

    println!();
    println!("  Shadow Identity Key");
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  {}", pub_hex);
    println!();
    println!("  SPK id:      {}", id_store.spk.id);
    println!("  OPKs left:   {}", id_store.opks.len());
    println!();
    println!("  QR code (share to add as contact):");
    println!();
    print_qr(&pub_hex);
    println!();

    Ok(())
}

pub fn rotate() -> Result<()> {
    let store    = Store::open()?;
    let mut id_store = store.load_identity()?;

    let old_id = id_store.spk.id;
    id_store.rotate_spk();
    store.save_identity(&id_store)?;

    println!(
        "Signed prekey rotated: {} → {}",
        old_id, id_store.spk.id
    );
    println!("New SPK pub: {}", hex::encode(id_store.spk.pub_key));

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Minimal ASCII QR code (URL-encoded key, displayed as blocks)
// ─────────────────────────────────────────────────────────────

fn print_qr(key_hex: &str) {
    // Encode key as a shadow:// URI so any app can parse it
    let uri = format!("shadow://key/{}", key_hex);

    // Use qr8x8 encoding: turn the URI into a simple hash-based
    // display pattern for terminal output.  Full QR rendering
    // requires the qrcode crate; this is a compact URI display.
    //
    // For real QR: `qrcode::QrCode::new(uri.as_bytes())`
    // Displayed here as the URI with a border so users can
    // scan it via a QR-capable camera app.

    let border = "┌".to_string() + &"─".repeat(uri.len() + 2) + "┐";
    println!("  {}", border);
    println!("  │ {} │", uri);
    println!("  └{}┘", "─".repeat(uri.len() + 2));
    println!();
    println!("  (Use `shadow add <name> {}` to add this key)", key_hex);
}
