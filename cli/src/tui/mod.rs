mod app;
mod ui;

use anyhow::Result;
use app::App;

use crate::store::{Contact, Store};

pub async fn run_session(store: Store, contact: Contact) -> Result<()> {
    let mut app = App::new(store, contact)?;
    app.run().await
}
