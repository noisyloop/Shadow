//! TUI application state and event loop

use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::store::{Contact, Message, Store};

// ─────────────────────────────────────────────────────────────
// Application state
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Normal,
    Insert,
}

pub struct App {
    pub store:         Store,
    pub contact:       Contact,
    pub messages:      Vec<Message>,
    pub input:         String,
    pub mode:          Mode,
    pub scroll_offset: usize,
    pub should_quit:   bool,
    pub status_msg:    String,
    pub ns:            u32,   // current ratchet step (display only)
    pub spk_id:        u32,   // current SPK id (display only)
}

impl App {
    pub fn new(store: Store, contact: Contact) -> Result<Self> {
        let messages = store.load_messages(&contact)?;
        let id_store = store.load_identity()?;
        let ns = store
            .load_session(&contact)?
            .map(|s| s.ns)
            .unwrap_or(0);

        Ok(App {
            messages,
            input: String::new(),
            mode: Mode::Insert,
            scroll_offset: 0,
            should_quit: false,
            status_msg: format!("Chat with {} — i:insert  Esc:normal  q:quit", contact.name),
            ns,
            spk_id: id_store.spk.id,
            store,
            contact,
        })
    }

    // ── Event loop ────────────────────────────────────────────

    pub async fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let tick = Duration::from_millis(100);

        loop {
            terminal.draw(|f| super::ui::render(f, self))?;

            if event::poll(tick)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    self.handle_key(key.code, key.modifiers);
                }
            }

            if self.should_quit {
                break;
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }

    // ── Key handling ──────────────────────────────────────────

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        match self.mode {
            Mode::Normal => match code {
                KeyCode::Char('i') => self.mode = Mode::Insert,
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Up   | KeyCode::Char('k') => self.scroll_up(),
                KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
                _ => {}
            },
            Mode::Insert => match code {
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Enter => self.send_message(),
                KeyCode::Backspace => { self.input.pop(); }
                KeyCode::Char(c) => {
                    if modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                        self.should_quit = true;
                    } else {
                        self.input.push(c);
                    }
                }
                _ => {}
            },
        }
    }

    fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        let max = self.messages.len().saturating_sub(1);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
        }
    }

    fn send_message(&mut self) {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.input.clear();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Encrypt and save (session must exist)
        let result = self.encrypt_and_save(&text, ts);
        match result {
            Ok(_) => {
                self.status_msg = format!("Sent at {}", ts);
            }
            Err(e) => {
                self.status_msg = format!("Error: {e}");
            }
        }
    }

    fn encrypt_and_save(&mut self, text: &str, ts: i64) -> Result<()> {
        use crate::commands::send::derive_ad;
        use crate::crypto::ratchet::ratchet_encrypt;

        let id_store = self.store.load_identity()?;

        let mut state = self
            .store
            .load_session(&self.contact)?
            .ok_or_else(|| anyhow::anyhow!(
                "No active session. Exchange keys first (X3DH handshake)."
            ))?;

        let ad = derive_ad(&id_store.identity.ik_dh_pub, &self.contact.ik_dh_pub);
        let (_header, _ct) = ratchet_encrypt(&mut state, text.as_bytes(), &ad)?;
        self.ns = state.ns;
        self.store.save_session(&self.contact, &state)?;

        let msg_id = self.messages.len() as u64;
        let msg = Message {
            id: msg_id,
            from_me: true,
            text: text.to_string(),
            timestamp: ts,
            delivered: false,
        };
        self.store.append_message(&self.contact, msg.clone())?;
        self.messages.push(msg);

        // Scroll to bottom
        self.scroll_offset = self.messages.len().saturating_sub(1);
        Ok(())
    }
}
