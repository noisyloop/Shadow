//! Shadow — End-to-end encrypted communications
//! No phone number. No central identity authority.

mod commands;
mod crypto;
mod store;
mod transport;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

// ─────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "shadow",
    version = "0.1.0",
    about   = "End-to-end encrypted communications. No phone number. No central identity.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate device identity keypair and initialise local store
    Init,

    /// Add a contact by their public identity key
    Add {
        /// Contact name
        name: String,
        /// 64-character hex identity key (from `shadow key show`)
        pubkey: String,
        /// Optional Nostr public key (secp256k1 x-only, hex) for relay routing
        #[arg(long)]
        nostr: Option<String>,
    },

    /// Open an interactive chat session with a contact
    Send {
        /// Contact name
        contact: String,
        /// Send a single message non-interactively and exit
        #[arg(short, long)]
        message: Option<String>,
        /// Nostr relay URL to publish through (default: wss://relay.damus.io)
        #[arg(long)]
        relay: Option<String>,
    },

    /// Poll for new incoming messages from a Nostr relay
    Recv {
        /// Override default relay URL
        #[arg(long)]
        relay: Option<String>,
    },

    /// Key management subcommands
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Display your public identity key and QR code
    Show,
    /// Rotate the signed prekey (recommended weekly)
    Rotate,
}

// ─────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            commands::init::run()?;
        }

        Commands::Add { name, pubkey, nostr } => {
            commands::add::run(&name, &pubkey, nostr.as_deref())?;
        }

        Commands::Send { contact, message, relay } => {
            commands::send::run(&contact, message.as_deref(), relay.as_deref()).await?;
        }

        Commands::Recv { relay } => {
            commands::recv::run(relay.as_deref()).await?;
        }

        Commands::Key { action } => match action {
            KeyAction::Show   => commands::key::show()?,
            KeyAction::Rotate => commands::key::rotate()?,
        },
    }

    Ok(())
}
