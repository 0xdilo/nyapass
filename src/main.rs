use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use arboard::Clipboard;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use rand::{rngs::OsRng, Rng};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::PathBuf};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    name: String,
    username: String,
    password: String,
    url: String,
    notes: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Category {
    name: String,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    categories: Vec<Category>,
}

struct App {
    vault: Vault,
    key: Vec<u8>,
    salt: [u8; 16],
    vault_path: PathBuf,
    view: View,
    cat_state: ListState,
    entry_state: ListState,
    input: String,
    input_cursor: usize,
    input_field: usize,
    form_fields: Vec<String>,
    search: String,
    search_idx: usize,
    message: Option<String>,
    show_password: bool,
    modified: bool,
}

#[derive(PartialEq, Clone)]
enum View {
    Categories,
    Entries,
    AddCategory,
    AddEntry,
    EditEntry,
    Search,
    SearchCategory,
    Confirm(String, Box<View>),
    GeneratePassword,
}

fn vault_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nyapass")
        .join("vault.enc")
}

fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let salt_str = SaltString::encode_b64(salt).unwrap();
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap();
    hash.hash.unwrap().as_bytes()[..32].to_vec()
}

fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data).unwrap();
    [nonce_bytes.to_vec(), ciphertext].concat()
}

fn decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(&data[..12]);
    cipher.decrypt(nonce, &data[12..]).ok()
}

fn generate_password(length: usize, use_symbols: bool) -> String {
    let mut chars: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    if use_symbols {
        chars.extend("!@#$%^&*()_+-=[]{}|;:,.<>?".chars());
    }
    (0..length)
        .map(|_| chars[OsRng.gen_range(0..chars.len())])
        .collect()
}

impl App {
    fn new(key: Vec<u8>, salt: [u8; 16], vault: Vault, vault_path: PathBuf) -> Self {
        let mut app = Self {
            vault,
            key,
            salt,
            vault_path,
            view: View::Categories,
            cat_state: ListState::default(),
            entry_state: ListState::default(),
            input: String::new(),
            input_cursor: 0,
            input_field: 0,
            form_fields: vec![String::new(); 5],
            search: String::new(),
            search_idx: 0,
            message: None,
            show_password: false,
            modified: false,
        };
        if !app.vault.categories.is_empty() {
            app.cat_state.select(Some(0));
        }
        app
    }

    fn save(&mut self) -> io::Result<()> {
        let json = serde_json::to_vec(&self.vault)?;
        let encrypted = encrypt(&json, &self.key);
        let full = [self.salt.to_vec(), encrypted].concat();
        if let Some(parent) = self.vault_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.vault_path, full)?;
        self.modified = false;
        self.message = Some("Saved!".into());
        Ok(())
    }

    fn current_category(&self) -> Option<&Category> {
        self.cat_state
            .selected()
            .and_then(|i| self.vault.categories.get(i))
    }

    fn current_entry(&self) -> Option<&Entry> {
        let cat = self.current_category()?;
        self.entry_state.selected().and_then(|i| cat.entries.get(i))
    }

    fn filtered_entries(&self) -> Vec<(usize, &Entry)> {
        let Some(cat) = self.current_category() else {
            return vec![];
        };
        if self.search.is_empty() {
            cat.entries.iter().enumerate().collect()
        } else {
            let q = self.search.to_lowercase();
            cat.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.name.to_lowercase().contains(&q)
                        || e.username.to_lowercase().contains(&q)
                        || e.url.to_lowercase().contains(&q)
                })
                .collect()
        }
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        use std::process::{Command, Stdio};
        let copied = Command::new("wl-copy")
            .arg(text)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
            || Clipboard::new()
                .and_then(|mut c| c.set_text(text.to_string()))
                .is_ok();
        if copied {
            self.message = Some("copied!".into());
        } else {
            self.message = Some("copy failed".into());
        }
    }

    fn global_search(&self) -> Vec<(usize, usize, &Entry)> {
        if self.search.is_empty() {
            return vec![];
        }
        let q = self.search.to_lowercase();
        self.vault
            .categories
            .iter()
            .enumerate()
            .flat_map(|(ci, cat)| {
                cat.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| {
                        e.name.to_lowercase().contains(&q)
                            || e.username.to_lowercase().contains(&q)
                            || e.url.to_lowercase().contains(&q)
                    })
                    .map(move |(ei, e)| (ci, ei, e))
            })
            .collect()
    }
}

fn main() -> io::Result<()> {
    let vault_path = vault_path();
    let exists = vault_path.exists();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut password = String::new();
    let mut confirm = String::new();
    let mut confirming = false;
    let mut error_msg: Option<String> = None;

    loop {
        terminal.draw(|f| {
            let area = centered_rect(50, 7, f.area());
            let block = Block::default()
                .title(if exists {
                    " unlock vault "
                } else {
                    " create vault "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta));

            let inner = block.inner(area);
            f.render_widget(Clear, area);
            f.render_widget(block, area);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(inner);

            let label = if !exists && confirming {
                "confirm: "
            } else {
                "password: "
            };
            let display = if !exists && confirming {
                &confirm
            } else {
                &password
            };
            let masked: String = "*".repeat(display.len());

            f.render_widget(Paragraph::new(format!("{}{}", label, masked)), chunks[0]);

            if let Some(ref e) = error_msg {
                f.render_widget(
                    Paragraph::new(e.as_str()).style(Style::default().fg(Color::Red)),
                    chunks[2],
                );
            }
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            error_msg = None;
            let target = if !exists && confirming {
                &mut confirm
            } else {
                &mut password
            };

            match key.code {
                KeyCode::Char(c) => target.push(c),
                KeyCode::Backspace => {
                    target.pop();
                }
                KeyCode::Esc => {
                    disable_raw_mode()?;
                    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                    return Ok(());
                }
                KeyCode::Enter => {
                    if exists {
                        let data = fs::read(&vault_path)?;
                        if data.len() < 28 {
                            error_msg = Some("corrupted vault".into());
                            password.clear();
                            continue;
                        }
                        let salt: [u8; 16] = data[..16].try_into().unwrap();
                        let encrypted = &data[16..];
                        let key = derive_key(&password, &salt);
                        if let Some(decrypted) = decrypt(encrypted, &key) {
                            if let Ok(vault) = serde_json::from_slice::<Vault>(&decrypted) {
                                password.zeroize();
                                run_app(
                                    &mut terminal,
                                    App::new(key, salt, vault, vault_path.clone()),
                                )?;
                                break;
                            }
                        }
                        error_msg = Some("wrong password".into());
                        password.clear();
                    } else if !confirming {
                        if password.len() < 4 {
                            error_msg = Some("password too short".into());
                            continue;
                        }
                        confirming = true;
                    } else if password == confirm {
                        let mut salt = [0u8; 16];
                        OsRng.fill(&mut salt);
                        let key = derive_key(&password, &salt);
                        let vault = Vault::default();
                        let json = serde_json::to_vec(&vault)?;
                        let encrypted = encrypt(&json, &key);
                        let full = [salt.to_vec(), encrypted].concat();
                        if let Some(parent) = vault_path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::write(&vault_path, full)?;
                        password.zeroize();
                        confirm.zeroize();
                        run_app(
                            &mut terminal,
                            App::new(key, salt, vault, vault_path.clone()),
                        )?;
                        break;
                    } else {
                        error_msg = Some("passwords don't match".into());
                        confirm.clear();
                        confirming = false;
                        password.clear();
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            app.message = None;

            if let View::Confirm(_, ref prev) = app.view.clone() {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if let View::Confirm(action, _) = &app.view {
                            if action == "delete_category" {
                                if let Some(i) = app.cat_state.selected() {
                                    app.vault.categories.remove(i);
                                    if app.vault.categories.is_empty() {
                                        app.cat_state.select(None);
                                    } else {
                                        app.cat_state.select(Some(
                                            i.saturating_sub(1).min(app.vault.categories.len() - 1),
                                        ));
                                    }
                                    app.modified = true;
                                }
                            } else if action == "delete_entry" {
                                let entry_idx = app.entry_state.selected();
                                let cat_idx = app.cat_state.selected();
                                if let (Some(ci), Some(ei)) = (cat_idx, entry_idx) {
                                    let entries_len = app.vault.categories[ci].entries.len();
                                    app.vault.categories[ci].entries.remove(ei);
                                    if entries_len <= 1 {
                                        app.entry_state.select(None);
                                    } else {
                                        app.entry_state.select(Some(
                                            ei.saturating_sub(1).min(entries_len - 2),
                                        ));
                                    }
                                    app.modified = true;
                                }
                            }
                        }
                        app.view = *prev.clone();
                    }
                    _ => app.view = *prev.clone(),
                }
                continue;
            }

            match &app.view {
                View::Categories => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = app.save();
                    }
                    KeyCode::Char('a') => {
                        app.input.clear();
                        app.input_cursor = 0;
                        app.view = View::AddCategory;
                    }
                    KeyCode::Char('d') => {
                        if app.cat_state.selected().is_some() {
                            app.view =
                                View::Confirm("delete_category".into(), Box::new(View::Categories));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(i) = app.cat_state.selected() {
                            app.cat_state.select(Some(i.saturating_sub(1)));
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(i) = app.cat_state.selected() {
                            let len = app.vault.categories.len();
                            if len > 0 {
                                app.cat_state.select(Some((i + 1).min(len - 1)));
                            }
                        }
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        if app.cat_state.selected().is_some() && app.current_category().is_some() {
                            app.entry_state.select(
                                if app.current_category().unwrap().entries.is_empty() {
                                    None
                                } else {
                                    Some(0)
                                },
                            );
                            app.search.clear();
                            app.view = View::Entries;
                        }
                    }
                    KeyCode::Char('/') => {
                        app.search.clear();
                        app.view = View::SearchCategory;
                    }
                    _ => {}
                },
                View::Entries => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
                        app.view = View::Categories;
                    }
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = app.save();
                    }
                    KeyCode::Char('a') => {
                        app.form_fields = vec![String::new(); 5];
                        app.input_field = 0;
                        app.view = View::AddEntry;
                    }
                    KeyCode::Char('e') => {
                        if let Some(entry) = app.current_entry() {
                            app.form_fields = vec![
                                entry.name.clone(),
                                entry.username.clone(),
                                entry.password.clone(),
                                entry.url.clone(),
                                entry.notes.clone(),
                            ];
                            app.input_field = 0;
                            app.view = View::EditEntry;
                        }
                    }
                    KeyCode::Char('d') => {
                        if app.entry_state.selected().is_some() {
                            app.view =
                                View::Confirm("delete_entry".into(), Box::new(View::Entries));
                        }
                    }
                    KeyCode::Char('c') => {
                        if let Some(entry) = app.current_entry() {
                            let pass = entry.password.clone();
                            app.copy_to_clipboard(&pass);
                        }
                    }
                    KeyCode::Char('u') => {
                        if let Some(entry) = app.current_entry() {
                            let user = entry.username.clone();
                            app.copy_to_clipboard(&user);
                        }
                    }
                    KeyCode::Char('p') => {
                        app.show_password = !app.show_password;
                    }
                    KeyCode::Char('/') => {
                        app.search.clear();
                        app.view = View::Search;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let filtered = app.filtered_entries();
                        if let Some(i) = app.entry_state.selected() {
                            if i > 0 {
                                let prev_idx = filtered.iter().position(|(idx, _)| *idx == i);
                                if let Some(pos) = prev_idx {
                                    if pos > 0 {
                                        app.entry_state.select(Some(filtered[pos - 1].0));
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let filtered = app.filtered_entries();
                        if !filtered.is_empty() {
                            if let Some(i) = app.entry_state.selected() {
                                let curr_pos = filtered.iter().position(|(idx, _)| *idx == i);
                                if let Some(pos) = curr_pos {
                                    if pos + 1 < filtered.len() {
                                        app.entry_state.select(Some(filtered[pos + 1].0));
                                    }
                                }
                            } else {
                                app.entry_state.select(Some(filtered[0].0));
                            }
                        }
                    }
                    _ => {}
                },
                View::AddCategory => match key.code {
                    KeyCode::Esc => app.view = View::Categories,
                    KeyCode::Char(c) => {
                        app.input.insert(app.input_cursor, c);
                        app.input_cursor += 1;
                    }
                    KeyCode::Backspace => {
                        if app.input_cursor > 0 {
                            app.input_cursor -= 1;
                            app.input.remove(app.input_cursor);
                        }
                    }
                    KeyCode::Left => app.input_cursor = app.input_cursor.saturating_sub(1),
                    KeyCode::Right => {
                        app.input_cursor = (app.input_cursor + 1).min(app.input.len())
                    }
                    KeyCode::Enter => {
                        if !app.input.trim().is_empty() {
                            app.vault.categories.push(Category {
                                name: app.input.trim().to_string(),
                                entries: vec![],
                            });
                            app.cat_state.select(Some(app.vault.categories.len() - 1));
                            app.modified = true;
                        }
                        app.view = View::Categories;
                    }
                    _ => {}
                },
                View::AddEntry | View::EditEntry => {
                    let is_edit = app.view == View::EditEntry;
                    match key.code {
                        KeyCode::Esc => app.view = View::Entries,
                        KeyCode::Tab | KeyCode::Down => {
                            app.input_field = (app.input_field + 1) % 5;
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            app.input_field = if app.input_field == 0 {
                                4
                            } else {
                                app.input_field - 1
                            };
                        }
                        KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.view = View::GeneratePassword;
                        }
                        KeyCode::Char(c) => {
                            app.form_fields[app.input_field].push(c);
                        }
                        KeyCode::Backspace => {
                            app.form_fields[app.input_field].pop();
                        }
                        KeyCode::F(2) | KeyCode::Enter if app.input_field == 4 => {
                            let entry = Entry {
                                name: app.form_fields[0].trim().to_string(),
                                username: app.form_fields[1].trim().to_string(),
                                password: app.form_fields[2].clone(),
                                url: app.form_fields[3].trim().to_string(),
                                notes: app.form_fields[4].trim().to_string(),
                            };
                            if !entry.name.is_empty() {
                                let cat_idx = app.cat_state.selected();
                                let entry_idx = app.entry_state.selected();
                                if let Some(ci) = cat_idx {
                                    if is_edit {
                                        if let Some(ei) = entry_idx {
                                            app.vault.categories[ci].entries[ei] = entry;
                                        }
                                    } else {
                                        app.vault.categories[ci].entries.push(entry);
                                        let new_len = app.vault.categories[ci].entries.len();
                                        app.entry_state.select(Some(new_len - 1));
                                    }
                                    app.modified = true;
                                }
                            }
                            app.view = View::Entries;
                        }
                        _ => {}
                    }
                }
                View::Search => match key.code {
                    KeyCode::Esc => {
                        app.search.clear();
                        app.view = View::Entries;
                    }
                    KeyCode::Enter => {
                        let filtered = app.filtered_entries();
                        if !filtered.is_empty() {
                            app.entry_state.select(Some(filtered[0].0));
                        }
                        app.view = View::Entries;
                    }
                    KeyCode::Char(c) => app.search.push(c),
                    KeyCode::Backspace => {
                        app.search.pop();
                    }
                    _ => {}
                },
                View::SearchCategory => match key.code {
                    KeyCode::Esc => {
                        app.search.clear();
                        app.search_idx = 0;
                        app.view = View::Categories;
                    }
                    KeyCode::Enter => {
                        let results = app.global_search();
                        if let Some(&(ci, ei, _)) = results.get(app.search_idx) {
                            app.cat_state.select(Some(ci));
                            app.entry_state.select(Some(ei));
                            app.search.clear();
                            app.search_idx = 0;
                            app.view = View::Entries;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.search_idx > 0 {
                            app.search_idx -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let len = app.global_search().len();
                        if app.search_idx + 1 < len {
                            app.search_idx += 1;
                        }
                    }
                    KeyCode::Char(c) => {
                        app.search.push(c);
                        app.search_idx = 0;
                    }
                    KeyCode::Backspace => {
                        app.search.pop();
                        app.search_idx = 0;
                    }
                    _ => {}
                },
                View::GeneratePassword => match key.code {
                    KeyCode::Esc => app.view = View::AddEntry,
                    KeyCode::Char('1') => {
                        app.form_fields[2] = generate_password(16, false);
                        app.view = if app.form_fields[0].is_empty() {
                            View::AddEntry
                        } else {
                            View::EditEntry
                        };
                    }
                    KeyCode::Char('2') => {
                        app.form_fields[2] = generate_password(16, true);
                        app.view = if app.form_fields[0].is_empty() {
                            View::AddEntry
                        } else {
                            View::EditEntry
                        };
                    }
                    KeyCode::Char('3') => {
                        app.form_fields[2] = generate_password(24, true);
                        app.view = if app.form_fields[0].is_empty() {
                            View::AddEntry
                        } else {
                            View::EditEntry
                        };
                    }
                    KeyCode::Char('4') => {
                        app.form_fields[2] = generate_password(32, true);
                        app.view = if app.form_fields[0].is_empty() {
                            View::AddEntry
                        } else {
                            View::EditEntry
                        };
                    }
                    _ => {}
                },
                View::Confirm(_, _) => {}
            }
        }
    }

    if app.modified {
        let _ = app.save();
    }

    Ok(())
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(f.area());

    match &app.view {
        View::Categories | View::AddCategory | View::SearchCategory => {
            draw_categories(f, app, chunks[0])
        }
        View::Entries | View::Search => draw_entries(f, app, chunks[0]),
        View::AddEntry | View::EditEntry | View::GeneratePassword => {
            draw_entry_form(f, app, chunks[0])
        }
        View::Confirm(_, _) => {
            draw_entries(f, app, chunks[0]);
            draw_confirm(f, app);
        }
    }

    draw_status(f, app, chunks[1]);
}

fn draw_categories(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let items: Vec<ListItem> = app
        .vault
        .categories
        .iter()
        .map(|c| {
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(&c.name, Style::default().fg(Color::White)),
                Span::styled(
                    format!("  {} entries", c.entries.len()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" categories ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Magenta)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ▸");

    f.render_stateful_widget(list, chunks[0], &mut app.cat_state);

    let style = Style::default().fg(Color::Magenta);
    let logo = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "    nyapass",
            style.add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled("    /\\_____/\\", style)),
        Line::from(Span::styled("   /  o   o  \\", style)),
        Line::from(Span::styled("  ( ==  ^  == )", style)),
        Line::from(Span::styled("   )         (", style)),
        Line::from(Span::styled("  (           )", style)),
        Line::from(Span::styled(" ( (  )   (  ) )", style)),
        Line::from(Span::styled(" (__(__)___(__)__)", style)),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(logo, chunks[1]);

    if app.view == View::AddCategory {
        let popup = centered_rect(50, 5, f.area());
        f.render_widget(Clear, popup);
        let block = Block::default()
            .title(" new category ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(popup);
        f.render_widget(block, popup);
        f.render_widget(Paragraph::new(app.input.as_str()), inner);
        f.set_cursor_position((inner.x + app.input_cursor as u16, inner.y));
    }

    if app.view == View::SearchCategory {
        let results = app.global_search();
        let height = (results.len().min(8) + 4) as u16;
        let popup = centered_rect(60, height, f.area());
        f.render_widget(Clear, popup);
        let block = Block::default()
            .title(format!(" search [{}] ", app.search))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(popup);
        f.render_widget(block, popup);

        let search_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(inner);

        f.render_widget(Paragraph::new(app.search.as_str()), search_chunks[0]);
        f.set_cursor_position((
            search_chunks[0].x + app.search.len() as u16,
            search_chunks[0].y,
        ));

        let result_items: Vec<ListItem> = results
            .iter()
            .enumerate()
            .take(8)
            .map(|(i, (ci, _, e))| {
                let cat_name = &app.vault.categories[*ci].name;
                let style = if i == app.search_idx {
                    Style::default().bg(Color::Yellow).fg(Color::Black)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!(" {} ", e.name), style),
                    Span::styled(
                        format!("({})", cat_name),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let result_list = List::new(result_items);
        f.render_widget(result_list, search_chunks[2]);
    }
}

fn draw_entries(f: &mut Frame, app: &mut App, area: Rect) {
    let cat_name = app
        .current_category()
        .map(|c| c.name.clone())
        .unwrap_or_default();

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let filtered = app.filtered_entries();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|(_, e)| ListItem::new(format!("  {}", e.name)))
        .collect();

    let title = if app.search.is_empty() {
        format!(" {} ", cat_name)
    } else {
        format!(" {} [search: {}] ", cat_name, app.search)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .highlight_style(Style::default().bg(Color::Magenta).fg(Color::Black))
        .highlight_symbol("▸ ");

    let mut list_state = ListState::default();
    if let Some(sel) = app.entry_state.selected() {
        list_state.select(filtered.iter().position(|(i, _)| *i == sel));
    }
    f.render_stateful_widget(list, chunks[0], &mut list_state);

    let detail_block = Block::default()
        .title(" details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    if let Some(entry) = app.current_entry() {
        let pass_display = if app.show_password {
            entry.password.clone()
        } else {
            "*".repeat(entry.password.len().min(20))
        };

        let text = vec![
            Line::from(vec![
                Span::styled("name:     ", Style::default().fg(Color::DarkGray)),
                Span::raw(&entry.name),
            ]),
            Line::from(vec![
                Span::styled("username: ", Style::default().fg(Color::DarkGray)),
                Span::raw(&entry.username),
            ]),
            Line::from(vec![
                Span::styled("password: ", Style::default().fg(Color::DarkGray)),
                Span::raw(pass_display),
            ]),
            Line::from(vec![
                Span::styled("url:      ", Style::default().fg(Color::DarkGray)),
                Span::raw(&entry.url),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "notes: ",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(entry.notes.as_str()),
        ];

        let p = Paragraph::new(text).block(detail_block);
        f.render_widget(p, chunks[1]);
    } else {
        f.render_widget(detail_block, chunks[1]);
    }

    if app.view == View::Search {
        let popup = centered_rect(40, 3, f.area());
        f.render_widget(Clear, popup);
        let block = Block::default()
            .title(" search ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(popup);
        f.render_widget(block, popup);
        f.render_widget(Paragraph::new(app.search.as_str()), inner);
        f.set_cursor_position((inner.x + app.search.len() as u16, inner.y));
    }
}

fn draw_entry_form(f: &mut Frame, app: &mut App, area: Rect) {
    let labels = ["name", "username", "password", "url", "notes"];
    let block = Block::default()
        .title(if app.view == View::EditEntry {
            " edit entry "
        } else {
            " new entry "
        })
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(inner);

    for (i, label) in labels.iter().enumerate() {
        let style = if i == app.input_field {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let display = if i == 2 && !app.show_password {
            "*".repeat(app.form_fields[i].len())
        } else {
            app.form_fields[i].clone()
        };

        let p = Paragraph::new(display).block(
            Block::default()
                .title(*label)
                .borders(Borders::ALL)
                .border_style(style),
        );
        f.render_widget(p, chunks[i]);

        if i == app.input_field {
            let x = chunks[i].x + 1 + app.form_fields[i].len() as u16;
            let y = chunks[i].y + 1;
            f.set_cursor_position((x, y));
        }
    }

    if app.view == View::GeneratePassword {
        let popup = centered_rect(35, 8, f.area());
        f.render_widget(Clear, popup);
        let block = Block::default()
            .title(" generate password ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green));
        let inner = block.inner(popup);
        f.render_widget(block, popup);

        let text = vec![
            Line::from("1) 16 chars (alphanumeric)"),
            Line::from("2) 16 chars (with symbols)"),
            Line::from("3) 24 chars (with symbols)"),
            Line::from("4) 32 chars (with symbols)"),
        ];
        f.render_widget(Paragraph::new(text), inner);
    }
}

fn draw_confirm(f: &mut Frame, app: &App) {
    let popup = centered_rect(30, 5, f.area());
    f.render_widget(Clear, popup);

    let msg = if let View::Confirm(action, _) = &app.view {
        if action == "delete_category" {
            "delete category?"
        } else {
            "delete entry?"
        }
    } else {
        "confirm?"
    };

    let block = Block::default()
        .title(" confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(popup);
    f.render_widget(block, popup);
    f.render_widget(Paragraph::new(format!("{}\n\n[y]es / [n]o", msg)), inner);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let help = match &app.view {
        View::Categories | View::SearchCategory => {
            "a:add d:del /:search enter:open ctrl+s:save q:quit"
        }
        View::Entries => "a:add e:edit d:del c:copy-pass u:copy-user p:show /:search h:back",
        View::AddCategory | View::Search => "enter:confirm  esc:cancel",
        View::AddEntry | View::EditEntry => {
            "tab:next ctrl+g:gen-pass F2/enter(notes):save esc:cancel"
        }
        View::GeneratePassword => "1-4:select  esc:cancel",
        View::Confirm(_, _) => "y:yes  n:no",
    };

    let modified = if app.modified { " [modified]" } else { "" };
    let msg = app.message.as_deref().unwrap_or("");

    let text = vec![
        Line::from(Span::styled(help, Style::default().fg(Color::DarkGray))),
        Line::from(vec![
            Span::styled(
                modified,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg, Style::default().fg(Color::Green)),
        ]),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(p, area);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let popup_width = area.width * percent_x / 100;
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, popup_width, height)
}
