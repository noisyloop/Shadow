//! `shadow init` — generate device identity

use anyhow::Result;

use crate::store::{IdentityStore, Store};

pub fn run() -> Result<()> {
    let store = Store::open()?;

    if store.is_initialised() {
        eprintln!("Shadow is already initialised. To reset, remove ~/.shadow/");
        return Ok(());
    }

    let id_store = IdentityStore::new();
    let pub_hex  = id_store.identity_pub_hex();
    store.save_identity(&id_store)?;

    println!("Shadow identity initialised.");
    println!();
    println!("  Identity key (share this to receive messages):");
    println!("  {}", pub_hex);
    println!();
    println!("  SPK id:   {}", id_store.spk.id);
    println!("  OPKs:     {} generated", id_store.opks.len());
    println!();
    println!("  Store:    {}", crate::store::shadow_dir().display());

    Ok(())
}
