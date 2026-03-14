//! TUI render function

use ratatui::{
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, Mode};

// ─────────────────────────────────────────────────────────────
// Layout
//
//  ┌─ title bar ────────────────────────────────────────────┐
//  │ Shadow  •  <contact>  •  ratchet step: N  •  SPK: K   │
//  ├─ messages ────────────────────────────────────────────-┤
//  │ [10:32] Hello, world!                                  │
//  │                                         [10:33] Hi!  ↵│
//  ├─ input ────────────────────────────────────────────────┤
//  │ > _                                                    │
//  ├─ status bar ───────────────────────────────────────────┤
//  │ i:insert  Esc:normal  ↑↓:scroll  q:quit               │
//  └────────────────────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // title bar
            Constraint::Min(3),     // messages
            Constraint::Length(3),  // input
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    render_title(f, app, outer[0]);
    render_messages(f, app, outer[1]);
    render_input(f, app, outer[2]);
    render_status(f, app, outer[3]);
}

fn render_title(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title = format!(
        " Shadow  •  {}  •  ratchet step: {}  •  SPK: {} ",
        app.contact.name,
        app.ns,
        app.spk_id,
    );
    let p = Paragraph::new(title)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Left);
    f.render_widget(p, area);
}

fn render_messages(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(format!(" {} ", app.contact.name));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let width  = inner.width as usize;
    let height = inner.height as usize;

    let items: Vec<ListItem> = app
        .messages
        .iter()
        .map(|msg| {
            let ts = format_ts(msg.timestamp);
            let line = if msg.from_me {
                let label = format!("{} [me]", ts);
                let pad   = width.saturating_sub(label.len() + msg.text.len() + 1);
                Line::from(vec![
                    Span::raw(" ".repeat(pad)),
                    Span::styled(&msg.text, Style::default().fg(Color::Cyan)),
                    Span::styled(format!(" {}", label), Style::default().fg(Color::DarkGray)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(format!("{} ", ts), Style::default().fg(Color::DarkGray)),
                    Span::raw(&msg.text),
                ])
            };
            ListItem::new(line)
        })
        .collect();

    // Show last `height` messages, offset by scroll
    let total = items.len();
    let start = if total > height {
        total.saturating_sub(height + app.scroll_offset)
    } else {
        0
    };
    let visible: Vec<ListItem> = items.into_iter().skip(start).take(height).collect();

    let list = List::new(visible);
    f.render_widget(list, inner);
}

fn render_input(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let mode_indicator = match app.mode {
        Mode::Insert => Span::styled("[INSERT]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Mode::Normal => Span::styled("[NORMAL]", Style::default().fg(Color::Yellow)),
    };
    let prompt = Span::styled(" > ", Style::default().fg(Color::White));
    let input_text = Span::raw(app.input.as_str());
    let cursor = if matches!(app.mode, Mode::Insert) {
        Span::styled("█", Style::default().fg(Color::White))
    } else {
        Span::raw("")
    };

    let line = Line::from(vec![prompt, input_text, cursor]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(match app.mode {
            Mode::Insert => Color::Green,
            Mode::Normal => Color::DarkGray,
        }))
        .title(Line::from(vec![Span::raw(" "), mode_indicator, Span::raw(" ")]));

    let p = Paragraph::new(line)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn render_status(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let p = Paragraph::new(format!(" {}", app.status_msg))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}

fn format_ts(ts: i64) -> String {
    // Simple HH:MM from unix timestamp (UTC)
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    format!("{:02}:{:02}", h, m)
}
