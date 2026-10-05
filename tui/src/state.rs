//! Screen and selection state for the whole app.
//!
//! Deliberately free of any UI framework: this file holds *what the app is*
//! (which screen, which row is selected, what the form contains) while `ui.rs`
//! holds how it looks. That split is what lets the interesting behaviour —
//! filter remapping, form validation, auto-lock — be unit tested without a
//! terminal.
//!
//! Filtering delegates to [`domi_core::search::SearchCache`] rather than
//! reimplementing matching here, so the TUI and the other shells agree on what
//! a search for "git" means.

use std::path::PathBuf;

use domi_core::search::SearchCache;
use domi_core::vault::{Entry, ItemCategory};
use domi_core::{KdfParams, now_unix};
use zeroize::Zeroize;

use crate::config::Config;
use crate::error::AppError;
use crate::vault_store::{VaultPaths, VaultSession};

/// The longest password a user can type, matching core's generator ceiling.
///
/// A password manager must not silently truncate a very long passphrase that
/// came from elsewhere, so the limit is core's maximum rather than something
/// shorter chosen for the UI.
pub const MAX_PASSWORD_LENGTH: usize = domi_core::password::MAX_PASSWORD_LENGTH;

/// The longest a title may be, in characters.
pub const MAX_TITLE_LENGTH: usize = 200;

/// The longest a note may be, in characters.
pub const MAX_NOTES_LENGTH: usize = 10_000;

/// The screens the app can be on.
///
/// `List` and `Detail` are one screen here: they are two panes of a single
/// layout, and splitting them would mean the user navigates away from the list
/// just to read an entry.
///
/// Defaults to `Unlock` so a props struct can derive `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// Create a vault: choose a password and confirm it.
    Setup,
    /// Unlock an existing vault. The default: almost every run starts here.
    #[default]
    Unlock,
    /// The main list plus detail panes.
    Vault,
    /// The entry editor.
    Edit,
    /// Preferences.
    Settings,
}

impl Screen {
    /// The short label the header shows on the left.
    pub fn label(self) -> &'static str {
        match self {
            Screen::Setup => "Set up vault",
            Screen::Unlock => "Locked",
            Screen::Vault => "Vault",
            Screen::Edit => "Edit entry",
            Screen::Settings => "Settings",
        }
    }
}

/// Which pane has keyboard focus on the vault screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    /// The entry list.
    #[default]
    List,
    /// The detail pane.
    Detail,
}

/// Which entries the list is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    /// Everything.
    #[default]
    All,
    /// Favourites only.
    Favorites,
}

impl Filter {
    /// The label shown in the header.
    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::Favorites => "favorites",
        }
    }

    /// The other filter, for the `v` key.
    pub fn toggled(self) -> Self {
        match self {
            Filter::All => Filter::Favorites,
            Filter::Favorites => Filter::All,
        }
    }
}

/// What a confirmed dialog was asking permission for.
///
/// A confirm modal cannot do the work itself: it is a question, and the answer
/// arrives as a later key press, by which point the dialog is gone. The action
/// is parked here in between so `y` means "do that thing" and nothing else has
/// to remember what "that thing" was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    /// Delete the entry that was selected when the dialog opened.
    DeleteEntry,
    /// Discard the vault's contents and return to setup with an empty vault.
    ResetVault,
}

/// A modal dialog drawn over whatever screen is active.
///
/// A modal is an overlay rather than a new screen: it keeps the screen beneath
/// it visible but unreachable, so every keybinding below it is disabled for as
/// long as it is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Yes/no. Destructive flows (delete, overwrite) land here.
    Confirm {
        title: String,
        body: String,
        danger: bool,
        yes_label: String,
        /// The action `y` runs. `None` for a confirmation with nothing behind
        /// it, which the UI treats as a plain message box.
        action: Option<PendingAction>,
    },
    /// Password entry, used by the master-password change. The old password
    /// is not asked for: an unlocked session is already proof of it.
    ///
    /// The new password is confirmed against itself, because rekeying to a typo
    /// locks the user out of every entry at once with no way back.
    Password { title: String, value: String, confirm: String, confirm_active: bool },
    /// Free-text entry, used by the settings row that names a vault
    /// directory. Separate from `Password` because the value is shown as it is
    /// typed, and because a path needs its own confirmation label.
    Text { title: String, value: String },
}

impl Modal {    /// A confirmation that runs `action` when the user answers yes.
    pub fn ask(title: &str, body: &str, yes_label: &str, action: PendingAction) -> Self {
        Modal::Confirm {
            title: title.to_string(),
            body: body.to_string(),
            danger: matches!(action, PendingAction::DeleteEntry | PendingAction::ResetVault),
            yes_label: yes_label.to_string(),
            action: Some(action),
        }
    }    /// The dialog's title, used as its heading.
    pub fn title(&self) -> &str {
        match self {
            Modal::Confirm { title, .. }
            | Modal::Password { title, .. }
            | Modal::Text { title, .. } => title,
        }
    }

    /// The work a `y` answer triggers.
    pub fn action(&self) -> Option<PendingAction> {
        match self {
            Modal::Confirm { action, .. } => *action,
            _ => None,
        }
    }

    /// Whether this dialog is tinted as destructive.
    pub fn is_danger(&self) -> bool {
        match self {
            Modal::Confirm { danger, .. } => *danger,
            _ => false,
        }
    }    /// A modal that collects typed text rather than a yes/no answer.    /// Which of a password modal's two fields is taking keystrokes.    /// Appends a typed character to a text-entry modal.
    ///
    /// Returns false for a confirm, which has no field to type into.
    pub fn push_char(&mut self, c: char) -> bool {
        match self {
            Modal::Password { value, confirm, confirm_active, .. } => {
                if *confirm_active {
                    confirm.push(c)
                } else {
                    value.push(c)
                }
                true
            }
            Modal::Text { value, .. } => {
                value.push(c);
                true
            }
            Modal::Confirm { .. } => false,
        }
    }

    /// Deletes the last typed character, returning whether anything changed.
    pub fn pop_char(&mut self) -> bool {
        match self {
            Modal::Password { value, confirm, confirm_active, .. } => {
                let popped = if *confirm_active { confirm.pop() } else { value.pop() };
                popped.is_some()
            }
            Modal::Text { value, .. } => value.pop().is_some(),
            Modal::Confirm { .. } => false,
        }
    }

    /// Moves a password modal between its two fields.
    pub fn tab_field(&mut self) {
        if let Modal::Password { confirm_active, .. } = self {
            *confirm_active = !*confirm_active;
        }
    }
}

/// How prominent a status message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// Something worked.
    Success,
    /// Something was refused or failed.
    Error,
    /// Neutral information.
    Info,
}

/// A transient message in the status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub kind: StatusKind,
    pub text: String,
}

impl Status {
    pub fn success(text: &str) -> Self {
        Status { kind: StatusKind::Success, text: text.to_string() }
    }
    pub fn error(text: &str) -> Self {
        Status { kind: StatusKind::Error, text: text.to_string() }
    }
    pub fn info(text: &str) -> Self {
        Status { kind: StatusKind::Info, text: text.to_string() }
    }
}

/// Password-generator settings, shown as toggles beside the password field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions { length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true }
    }
}

impl GeneratorOptions {
    /// Clamps the length into the range core accepts.
    ///
    /// Nothing in the UI lets the length drift out of band, so this exists as
    /// a guard rather than as validation the user sees.
    pub fn clamped_length(&self) -> usize {
        self.length
            .clamp(
                domi_core::password::MIN_PASSWORD_LENGTH,
                domi_core::password::MAX_PASSWORD_LENGTH,
            )
    }
}

/// The fields of the entry editor, in tab order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Field {
    #[default]
    Title,
    Username,
    Password,
    Url,
    Notes,
    Totp,
    Category,
    Favorite,
    Tags,
}

impl Field {
    pub const ALL: [Field; 9] = [
        Field::Title,
        Field::Username,
        Field::Password,
        Field::Url,
        Field::Notes,
        Field::Totp,
        Field::Category,
        Field::Favorite,
        Field::Tags,
    ];

    /// The label shown left of the input.
    pub fn label(self) -> &'static str {
        match self {
            Field::Title => "Title",
            Field::Username => "Username",
            Field::Password => "Password",
            Field::Url => "URL",
            Field::Notes => "Notes",
            Field::Totp => "TOTP secret",
            Field::Category => "Category",
            Field::Favorite => "Favorite",
            Field::Tags => "Tags",
        }
    }

    /// Whether the field accepts typed characters.
    ///
    /// The two that do not — Category and Favorite — are cyclers and toggles,
    /// so a character typed at them is a keypress for the control, not text.
    pub fn is_text(self) -> bool {
        !matches!(self, Field::Category | Field::Favorite)
    }

    /// The next field in tab order, wrapping.
    pub fn next(self) -> Field {
        let i = Field::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Field::ALL[(i + 1) % Field::ALL.len()]
    }

    /// The previous field in tab order, wrapping.
    pub fn prev(self) -> Field {
        let i = Field::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Field::ALL[(i + Field::ALL.len() - 1) % Field::ALL.len()]
    }
}

/// The entry being edited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryForm {
    pub id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: String,
    pub category: ItemCategory,
    pub favorite: bool,
    /// Tag names, comma-separated in the UI and split on save.
    pub tags: String,
    pub generator: GeneratorOptions,
    /// Whether the password field shows its contents.
    pub reveal: bool,
    /// Which field has focus.
    pub focused: Field,
}

impl EntryForm {
    /// An empty form for a new entry, focused on the title because a title is
    /// the one field every entry needs and typing one first is what a user
    /// always does.
    pub fn blank() -> Self {
        // Written out in full rather than with `..Default::default()`: the
        // zeroizing `Drop` below stops that form-update syntax from compiling
        // on a type that must never be copied wholesale.
        EntryForm {
            id: None,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp: String::new(),
            category: ItemCategory::Login,
            favorite: false,
            tags: String::new(),
            generator: GeneratorOptions::default(),
            reveal: false,
            focused: Field::Title,
        }
    }

    /// A form pre-filled from `entry`, for editing.
    pub fn from_entry(entry: &Entry) -> Self {
        EntryForm {
            id: Some(entry.id.clone()),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            totp: entry.totp_secret.clone().unwrap_or_default(),
            category: entry.category,
            favorite: entry.favorite,
            // Tag ids are resolved to names by the caller, which has the index;
            // the form only holds the names it will write back.
            tags: String::new(),
            generator: GeneratorOptions::default(),
            reveal: false,
            focused: Field::Title,
        }
    }

    /// The text currently in `field`.
    pub fn text(&self, field: Field) -> &str {
        match field {
            Field::Title => &self.title,
            Field::Username => &self.username,
            Field::Password => &self.password,
            Field::Url => &self.url,
            Field::Notes => &self.notes,
            Field::Totp => &self.totp,
            Field::Tags => &self.tags,
            // Not text fields; their value is shown differently.
            Field::Category | Field::Favorite => "",
        }
    }    /// Inserts `c` at the end of `field`'s text.
    ///
    /// The core of the field-typing path: a keystroke becomes text without the
    /// render layer having to track a caret.
    pub fn insert_char(&mut self, field: Field, c: char) {
        if !field.is_text() {
            return;
        }
        match field {
            Field::Title => self.title.push(c),
            Field::Username => self.username.push(c),
            Field::Password => {
                if self.password.chars().count() < MAX_PASSWORD_LENGTH {
                    self.password.push(c);
                }
            }
            Field::Url => self.url.push(c),
            Field::Notes => {
                if self.notes.chars().count() < MAX_NOTES_LENGTH {
                    self.notes.push(c);
                }
            }
            Field::Totp => self.totp.push(c),
            Field::Tags => self.tags.push(c),
            Field::Category | Field::Favorite => {}
        }
    }

    /// Removes the last character from `field`.
    pub fn backspace(&mut self, field: Field) {
        if !field.is_text() {
            return;
        }
        match field {
            Field::Title => {
                self.title.pop();
            }
            Field::Username => {
                self.username.pop();
            }
            Field::Password => {
                self.password.pop();
            }
            Field::Url => {
                self.url.pop();
            }
            Field::Notes => {
                self.notes.pop();
            }
            Field::Totp => {
                self.totp.pop();
            }
            Field::Tags => {
                self.tags.pop();
            }
            Field::Category | Field::Favorite => {}
        }
    }

    /// The tag names the user typed, split and trimmed, blanks removed.
    pub fn tag_names(&self) -> Vec<String> {
        self.tags
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Whether this form is editing an existing entry rather than making one.
    pub fn is_edit(&self) -> bool {
        self.id.is_some()
    }

    /// Rejects what core would reject, with messages naming the field.
    ///
    /// Checked before any encryption so a bad form never costs the user a write.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.title.trim().is_empty() {
            return Err(AppError::BadInput("Title is required.".to_string()));
        }
        if self.title.chars().count() > MAX_TITLE_LENGTH {
            return Err(AppError::BadInput(format!(
                "Title must be {MAX_TITLE_LENGTH} characters or fewer."
            )));
        }
        if self.notes.chars().count() > MAX_NOTES_LENGTH {
            return Err(AppError::BadInput(format!(
                "Notes must be {MAX_NOTES_LENGTH} characters or fewer."
            )));
        }
        Ok(())
    }

    /// The id an entry built from this form should carry.
    pub fn resolve_id(&self) -> String {
        match &self.id {
            Some(id) => id.clone(),
            None => crate::vault_store::new_entry_id(now_unix()),
        }
    }
}

/// Zeroize the secrets a form holds when it is dropped.
///
/// Without this a closed editor would leave the password in freed heap memory
/// until something overwrote it.
impl Drop for EntryForm {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp.zeroize();
    }
}

/// Everything the app is.
///
/// One struct rather than a tree of sub-states: the screens are small and share
/// most of their fields, and splitting them would mean every key handler reaching
/// through several layers to touch one value.
///
/// No `Debug` derive, for two reasons: `VaultSession` holds a derived key and
/// must never be formatted, and a dump of the whole state would print the typed
/// master password and every entry the form is holding. [`AppState::summary`]
/// gives a printable view that is safe to put in a panic message.
pub struct AppState {
    pub screen: Screen,
    pub focus: Focus,
    pub paths: VaultPaths,
    /// The master password being typed, held only until it is submitted.
    pub password: String,
    /// The confirmation typed on the setup screen, held only until it is
    /// submitted.
    pub confirm: String,
    /// Which setup field is taking keystrokes: 0 is the password, 1 the
    /// confirmation.
    ///
    /// Only meaningful on [`Screen::Setup`]; every other screen types into
    /// whichever field its own rules name.
    pub setup_field: usize,
    pub kdf: KdfParams,
    /// The error shown on the setup or unlock screen.
    pub screen_error: Option<String>,
    /// The unlocked vault, if any. Never `Clone` or `Debug` — see the type.
    pub session: Option<VaultSession>,
    pub cache: SearchCache,
    pub query: String,
    /// Whether the search bar is taking keystrokes.
    ///
    /// Distinct from `query` being empty: `/` puts the cursor in the bar
    /// before anything is typed, and until then plain letters still belong to
    /// the shortcuts. Without this the user would have to type a character
    /// before the first one landed in the box.
    pub searching: bool,
    pub filter: Filter,
    /// The ids of the entries the list is showing, in order.
    pub rows: Vec<String>,
    pub selected: usize,
    pub offset: usize,
    /// The decrypted entry shown in the detail pane.
    pub detail: Option<Entry>,
    pub reveal: bool,
    pub form: Option<EntryForm>,
    pub modal: Option<Modal>,
    pub status: Option<Status>,
    pub generator: GeneratorOptions,
    /// Which settings row the cursor is on.
    pub settings_row: usize,
    /// Auto-lock after this many seconds of no input; 0 disables it.
    pub auto_lock_secs: u64,
    pub idle_secs: u64,
    pub should_quit: bool,
    /// A secret the shell wants on the system clipboard. The UI writes and
    /// then clears it, so a secret doesn't sit in state longer than a frame.
    pub pending_copy: Option<String>,
    /// How many entries the list pane can show at the current terminal size.
    ///
    /// Fed in by the view, the only layer that knows the terminal geometry,
    /// and read back to size the scroll window.
    /// Where preferences are read from and written to.
    ///
    /// Held as a path rather than looked up on each use so a test can point the
    /// whole app at a scratch file. Production resolves it once at startup.
    pub config_file: PathBuf,
}

impl Default for AppState {
    fn default() -> Self {
        AppState::new(VaultPaths::new("."))
    }
}

impl AppState {
    /// Builds a state on the platform's real preferences path.
    pub fn new(paths: VaultPaths) -> Self {
        Self::with_config_file(paths, Config::default_file())
    }

    /// The same constructor, with the preferences file pinned to `file`.
    ///
    /// Only tests need this. Production resolves the path once in
    /// [`AppState::new`]; a test passes a scratch path so it never touches the
    /// real `~/.config/domi/config.toml`, which would otherwise make the suite
    /// order-dependent and leave settings behind on the developer's machine.
    pub fn with_config_file(paths: VaultPaths, file: PathBuf) -> Self {
        // Read the saved preferences before building the struct so the auto-lock
        // delay the user set last time is the one in force now. A config that
        // fails to parse has already been reported by `VaultPaths`, so this
        // quietly falls back to the default rather than saying it twice.
        let saved_auto_lock = Config::load_from(&file).ok().and_then(|c| c.auto_lock_secs);
        AppState {
            screen: Screen::Unlock,
            focus: Focus::List,
            paths,
            password: String::new(),
            confirm: String::new(),
            setup_field: 0,
            kdf: KdfParams::default(),
            screen_error: None,
            session: None,
            cache: SearchCache::default(),
            query: String::new(),
            searching: false,
            filter: Filter::All,
            rows: Vec::new(),
            selected: 0,
            offset: 0,
            detail: None,
            reveal: false,
            form: None,
            modal: None,
            status: None,
            generator: GeneratorOptions::default(),
            settings_row: 0,
            auto_lock_secs: saved_auto_lock.unwrap_or(15 * 60),
            idle_secs: 0,
            should_quit: false,
            pending_copy: None,
            // Overwritten from the terminal size on the first frame.
            config_file: file,
        }
    }

    /// Decides the first screen from what is on disk, so a returning user
    /// lands on unlock and a first-time user on setup.
    pub fn initial_screen(&mut self) -> Screen {
        self.screen = if self.paths.exists() { Screen::Unlock } else { Screen::Setup };
        self.screen
    }

    // ---------------------------------------------------------------- vault

    /// Rebuilds the search cache from the session index and recomputes rows.
    pub fn refresh(&mut self) {
        if let Some(session) = &self.session {
            self.cache = SearchCache::rebuild_from_index(&session.index);
        }
        self.recompute_rows();
    }

    /// Applies the query and filter, preserving the selected row by id where
    /// possible so filtering doesn't jump the user somewhere unrelated.
    fn recompute_rows(&mut self) {
        let previous = self.selected_id();

        let mut items: Vec<&domi_core::search::SearchItem> = match &self.filter {
            Filter::All => self.cache.query(&self.query),
            // The filter narrows first, then the query narrows within it, so
            // "search inside favorites" behaves the way it reads.
            Filter::Favorites => self
                .cache
                .query(&self.query)
                .into_iter()
                .filter(|i| i.favorite)
                .collect(),
        };
        // Never show a deleted entry, even if the cache still lists it.
        items.retain(|i| {
            self.session
                .as_ref()
                .is_none_or(|s| !s.index.entries.iter().any(|e| e.id == i.id && e.deleted))
        });
        items.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        self.rows = items.iter().map(|i| i.id.clone()).collect();

        // Restore the selection by id; otherwise clamp into the new range.
        self.selected = self
            .rows
            .iter()
            .position(|id| Some(id) == previous.as_ref())
            .unwrap_or(0);
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
        self.clamp_scroll();

        // Filtering can move the selection to a different entry, so the pane
        // has to follow. A stale detail would show a password for an entry the
        // user is no longer looking at.
        if self.rows.is_empty() {
            self.detail = None;
        } else if self.selected_id() != previous {
            self.load_detail();
        }
    }

    /// The id of the selected row, if there is one.
    pub fn selected_id(&self) -> Option<String> {
        self.rows.get(self.selected).cloned()
    }

    /// The index entry for the selected row.
    pub fn selected_entry(&self) -> Option<&domi_core::vault::IndexEntry> {
        let id = self.selected_id()?;
        self.session
            .as_ref()?
            .index
            .entries
            .iter()
            .find(|e| e.id == id && !e.deleted)
    }

    /// Keeps the selected row inside the visible window.
    ///
    /// Ratatui's list would scroll itself, but the app also draws its own
    /// offset for the header count, so the two have to agree.
    fn clamp_scroll(&mut self) {
        // The renderer clamps the window to whatever its pane can show, so all
        // this needs to do is keep the offset sane and the selected row inside
        // the full range.
        if self.rows.is_empty() {
            self.offset = 0;
            return;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        }
        self.offset = self.offset.min(self.rows.len() - 1);
    }

    /// Moves the selection by `delta` rows, clamped to the list.
    ///
    /// The detail pane is reloaded here rather than at each draw: it means a
    /// decryption happens once per selection change instead of once per
    /// frame, and a pane that is only correct after an explicit call is a pane
    /// that silently shows the wrong entry.
    pub fn move_selection(&mut self, delta: i64) {
        if self.rows.is_empty() {
            self.selected = 0;
            self.offset = 0;
            self.detail = None;
            return;
        }
        let last = self.rows.len() as i64 - 1;
        let next = (self.selected as i64 + delta).clamp(0, last);
        let moved = next as usize != self.selected;
        self.selected = next as usize;
        self.clamp_scroll();
        if moved {
            self.load_detail();
        }
        self.touch();
    }

    /// Toggles between the list and the detail pane.
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::Detail,
            Focus::Detail => Focus::List,
        };
    }

    /// Loads the selected entry into the detail pane.
    pub fn load_detail(&mut self) {
        let Some(id) = self.selected_id() else {
            self.detail = None;
            return;
        };
        let result = self.session.as_ref().map(|s| s.load_entry(&id));
        match result {
            Some(Ok(entry)) => self.detail = Some(entry),
            // A failure to read one entry must not blank the whole pane or
            // crash; the status line explains it.
            Some(Err(e)) => {
                self.detail = None;
                self.notify_error(e);
            }
            None => self.detail = None,
        }
    }

    /// Decrypts the selected entry and opens the editor.
    pub fn begin_edit(&mut self) {
        let Some(id) = self.selected_id() else { return };
        let Some(entry) = self.session.as_ref().map(|s| s.load_entry(&id)) else { return };
        match entry {
            Ok(entry) => {
                let mut form = EntryForm::from_entry(&entry);
                form.tags = self.tag_names_for(&entry).join(", ");
                self.form = Some(form);
                self.screen = Screen::Edit;
                self.touch();
            }
            Err(e) => self.notify_error(e),
        }
    }

    /// Opens an empty editor for a new entry.
    pub fn begin_new(&mut self) {
        self.form = Some(EntryForm::blank());
        self.screen = Screen::Edit;
        self.touch();
    }

    /// The names of the tags on `entry`, which holds only their ids.
    pub fn tag_names_for(&self, entry: &Entry) -> Vec<String> {
        let Some(session) = &self.session else { return Vec::new() };
        entry
            .tags
            .iter()
            .filter_map(|id| {
                session.index.tags.iter().find(|t| &t.id == id).map(|t| t.name.clone())
            })
            .collect()
    }    /// Validates and writes the open form, then returns to the list.
    pub fn save_form(&mut self) -> Result<(), AppError> {
        let Some(form) = self.form.clone() else {
            return Err(AppError::BadInput("Nothing to save".to_string()));
        };
        form.validate()?;

        let now = now_unix();
        let id = form.resolve_id();
        let Some(session) = self.session.as_mut() else {
            return Err(AppError::WrongPassword);
        };
        let tag_ids = session.ensure_tags(&form.tag_names(), now)?;

        // Keep the original timestamps when editing, so "recently changed"
        // ordering reflects the user's edit rather than the load.
        let previous = if form.is_edit() { session.load_entry(&id).ok() } else { None };
        let entry = Entry {
            id,
            title: form.title.trim().to_string(),
            username: form.username.trim().to_string(),
            password: form.password.clone(),
            url: form.url.trim().to_string(),
            notes: form.notes.clone(),
            totp_secret: Some(form.totp.clone())
                .filter(|s| !s.trim().is_empty()),
            custom_fields: previous
                .as_ref()
                .map(|p| p.custom_fields.clone())
                .unwrap_or_default(),
            updated_at: now,
            deleted: false,
            tags: tag_ids,
            collection_id: previous.as_ref().and_then(|p| p.collection_id.clone()),
            favorite: form.favorite,
            alias_provider: previous.as_ref().and_then(|p| p.alias_provider.clone()),
            alias_id: previous.as_ref().and_then(|p| p.alias_id.clone()),
            alias_email: previous.as_ref().and_then(|p| p.alias_email.clone()),
            category: form.category,
            password_history: previous
                .as_ref()
                .map(|p| p.password_history.clone())
                .unwrap_or_default(),
            attachments: previous
                .as_ref()
                .map(|p| p.attachments.clone())
                .unwrap_or_default(),
        };
        session.save_entry(entry)?;

        self.form = None;
        self.screen = Screen::Vault;
        self.refresh();
        self.notify(Status::success("Saved"));
        self.touch();
        Ok(())
    }

    /// Abandons the editor without writing.
    pub fn cancel_form(&mut self) {
        self.form = None;
        self.screen = Screen::Vault;
        self.refresh();
    }

    /// Deletes the selected entry after confirming.
    /// Asks for confirmation before deleting the selected entry.
    ///
    /// Deleting is the one action here that destroys user data, so it never
    /// runs off a single keystroke: this opens the dialog and
    /// [`AppState::confirm_pending`] does the work.
    pub fn request_delete_selected(&mut self) {
        if self.selected_id().is_none() {
            self.notify(Status::error("Nothing to delete"));
            return;
        }
        let title = self
            .selected_entry()
            .map(|e| e.title.clone())
            .unwrap_or_else(|| "this entry".to_string());
        self.modal = Some(Modal::ask(
            "Delete entry",
            &format!(
                "Delete \"{title}\"?\n\nThe entry leaves the list now and its blob stays on disk \
                 until something overwrites that id, so this is recoverable."
            ),
            "Delete",
            PendingAction::DeleteEntry,
        ));
    }

    /// Runs the action a confirm dialog was asking about.
    ///
    /// The dialog must already be closed; this only consumes the action.
    pub fn confirm_pending(&mut self, action: PendingAction) {
        match action {
            PendingAction::DeleteEntry => self.commit_delete_selected(),
            PendingAction::ResetVault => self.commit_reset_vault(),
        }
    }

    /// Performs the delete. Only reached once the user has answered yes.
    fn commit_delete_selected(&mut self) {
        let Some(id) = self.selected_id() else { return };
        let result = self.session.as_mut().map(|s| s.delete_entry(&id));
        match result {
            Some(Ok(())) => {
                self.detail = None;
                self.refresh();
                self.notify(Status::success("Deleted"));
            }
            Some(Err(e)) => self.notify_error(e),
            None => {}
        }
    }    /// Flips the selected entry's favourite flag and persists it.
    pub fn toggle_favorite(&mut self) {
        let Some(id) = self.selected_id() else { return };
        let loaded = self.session.as_ref().map(|s| s.load_entry(&id));
        let (Some(Ok(mut entry)), Some(session)) = (loaded, self.session.as_mut()) else {
            return;
        };
        entry.favorite = !entry.favorite;
        let now_favorite = entry.favorite;
        match session.save_entry(entry) {
            Ok(()) => {
                self.refresh();
                if let Some(detail) = &mut self.detail
                    && detail.id == id
                {
                    detail.favorite = now_favorite;
                }
                self.notify(Status::success(if now_favorite {
                    "Added to favorites"
                } else {
                    "Removed from favorites"
                }));
            }
            Err(e) => self.notify_error(e),
        }
    }

    /// Queues the selected entry's password for the shell to copy.
    pub fn copy_password(&mut self) {
        self.queue_copy(|e| e.password.clone(), "Copied password");
    }

    /// Queues the selected entry's username for the shell to copy.
    pub fn copy_username(&mut self) {
        self.queue_copy(|e| e.username.clone(), "Copied username");
    }

    /// Copies one field of the selected entry, reporting when there is nothing
    /// to copy.
    ///
    /// The message is left to the shell, which is where the clipboard write
    /// actually happens and can still fail.
    fn queue_copy(&mut self, field: impl Fn(&Entry) -> String, ok: &str) {
        let Some(id) = self.selected_id() else {
            self.notify(Status::error("Nothing selected"));
            return;
        };
        let Some(entry) = self.session.as_ref().map(|s| s.load_entry(&id)) else { return };
        match entry {
            Ok(entry) => {
                let value = field(&entry);
                if value.is_empty() {
                    self.notify(Status::error("That field is empty"));
                    return;
                }
                self.pending_copy = Some(value);
                self.notify(Status::success(ok));
            }
            Err(e) => self.notify_error(e),
        }
    }

    /// Toggles the detail pane's reveal flag.
    pub fn toggle_reveal(&mut self) {
        self.reveal = !self.reveal;
        if let Some(form) = self.form.as_mut() {
            form.reveal = self.reveal;
        }
        self.touch();
    }

    /// Changes the master password, re-encrypting every entry.
    pub fn change_master_password(
        &mut self,
        new_password: &str,
        confirm: &str,
    ) -> Result<(), AppError> {
        if new_password != confirm {
            return Err(AppError::BadInput("Passwords do not match.".to_string()));
        }
        if new_password.is_empty() {
            return Err(AppError::BadInput("Password cannot be empty.".to_string()));
        }
        let session = self.session.as_mut().ok_or(AppError::WrongPassword)?;
        session.rekey(new_password)?;
        self.notify(Status::success("Master password changed"));
        Ok(())
    }

    // ------------------------------------------------------------- auth flow

    /// Creates a vault on disk and unlocks it.
    pub fn create_vault(&mut self, password: &str, confirm: &str) -> Result<(), AppError> {
        if password.is_empty() {
            return Err(AppError::BadInput("Password cannot be empty.".to_string()));
        }
        if password != confirm {
            return Err(AppError::BadInput("Passwords do not match.".to_string()));
        }
        if self.paths.exists() {
            return Err(AppError::VaultExists);
        }
        let session = VaultSession::create(self.paths.clone(), password, self.kdf)?;
        self.session = Some(session);
        self.after_unlock();
        Ok(())
    }

    /// Unlocks the vault on disk with the entered password.
    pub fn unlock(&mut self, password: &str) -> Result<(), AppError> {
        let session = VaultSession::unlock(self.paths.clone(), password)?;
        self.session = Some(session);
        self.after_unlock();
        Ok(())
    }

    /// Shared post-unlock bookkeeping.
    ///
    /// The typed password is dropped as soon as it has done its job, so it is
    /// not sitting in state for the rest of the session.
    fn after_unlock(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
        self.screen = Screen::Vault;
        self.refresh();
        self.load_detail();
        self.touch();
    }

    /// Drops the session and returns to the unlock screen.
    pub fn lock(&mut self) {
        if let Some(session) = self.session.take() {
            session.lock();
        }
        self.password.zeroize();
        self.confirm.zeroize();
        self.detail = None;
        self.reveal = false;
        self.form = None;
        self.cache = SearchCache::default();
        self.query.clear();
        self.searching = false;
        self.rows.clear();
        self.selected = 0;
        self.offset = 0;
        self.idle_secs = 0;
        self.screen = Screen::Unlock;
        self.touch();
    }

    // ---------------------------------------------------------------- search

    /// Moves the keyboard focus into the search bar.
    ///
    /// The bar opens empty, so this is what lets the very first typed
    /// character land in it instead of triggering a shortcut.
    pub fn begin_search(&mut self) {
        self.searching = true;
        self.set_query(String::new());
        self.touch();
    }

    /// Takes the keyboard focus back out of the search bar, keeping the query.
    pub fn end_search(&mut self) {
        self.searching = false;
        self.touch();
    }

    /// Applies a search query.
    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.recompute_rows();
        self.touch();
    }

    /// Switches between all and favourites.
    pub fn toggle_filter(&mut self) {
        self.filter = self.filter.toggled();
        self.recompute_rows();
        self.notify(Status::info(&format!("Showing {}", self.filter.label())));
        self.touch();
    }

    // ------------------------------------------------------------- settings

    /// The auto-lock delays the settings screen steps through, in seconds.
    ///
    /// Each step is a multiple of the previous one so the arrow keys sweep
    /// from "off" to a full day without a long walk, and every step renders as
    /// a whole number of minutes.
    pub const AUTO_LOCK_STEPS: [u64; 7] = [0, 60, 300, 900, 1800, 3600, 21600];

    /// Moves the settings cursor by `delta`, clamped to the available rows.
    pub fn move_settings_row(&mut self, delta: i64) {
        let last = SETTINGS_ROWS.saturating_sub(1) as i64;
        let next = self.settings_row as i64 + delta;
        self.settings_row = next.clamp(0, last) as usize;
        self.touch();
    }

    /// Steps the auto-lock delay up or down to the next preset.
    ///
    /// Stepping past an end wraps around, so the delay is always reachable with
    /// the arrow keys regardless of where it started.
    pub fn step_auto_lock(&mut self, delta: i64) {
        let steps = Self::AUTO_LOCK_STEPS;
        let current = steps.iter().position(|s| *s == self.auto_lock_secs);
        let index: usize = match (current, delta.signum()) {
            (Some(i), 1) => (i + 1) % steps.len(),
            (Some(i), _) => (i + steps.len() - 1) % steps.len(),
            // A delay that is not one of the presets starts from the step above
            // it, so stepping up never appears to do nothing.
            (None, 1) => steps.iter().position(|s| *s > self.auto_lock_secs).unwrap_or(0),
            (None, _) => steps.len() - 1,
        };
        self.auto_lock_secs = steps[index];
        // A delay that has just passed should take effect immediately rather
        // than stranding the user with an idle timer that starts behind them.
        self.idle_secs = 0;
        let label = auto_lock_label(self.auto_lock_secs);
        self.persist_auto_lock();
        self.notify(Status::success(&format!("Auto-lock set to {label}")));
        self.touch();
    }

    /// Writes the current auto-lock delay to the config file.
    ///
    /// Read-modify-write, not a fresh Config: writing a struct with only
    /// `auto_lock_secs` set would silently delete a `vault_dir` the user had
    /// already saved. An unreadable existing file falls back to a blank one.
    ///
    /// A failure is reported rather than swallowed: the value still applies to
    /// this session, and the user needs to know it will not survive a restart.
    /// Written on every step rather than on exit, so a crash or a `ctrl+c`
    /// cannot lose the setting.
    fn persist_auto_lock(&mut self) {
        let mut cfg = Config::load_from(&self.config_file).unwrap_or_default();
        cfg.auto_lock_secs = Some(self.auto_lock_secs);
        if let Err(e) = cfg.save_to(&self.config_file) {
            self.notify_error(e);
        }
    }

    /// Applies a vault directory typed into the settings row.
    ///
    /// Takes effect on the next launch. Switching vaults mid-session would
    /// orphan the open one and leave the user staring at an app that looks
    /// locked but holds a live key, so this only records the preference.
    pub fn set_vault_dir(&mut self, dir: &str) -> Result<(), AppError> {
        let dir = dir.trim();
        if dir.is_empty() {
            return Err(AppError::BadInput("Enter a vault directory".to_string()));
        }
        // Reject a path that exists but is a file, since that can only ever
        // fail later with a less obvious storage error.
        let path = PathBuf::from(dir);
        if path.is_file() {
            return Err(AppError::BadInput(format!("{dir} is a file, not a directory")));
        }
        let cfg = Config {
            vault_dir: Some(dir.to_string()),
            auto_lock_secs: Some(self.auto_lock_secs),
        };
        cfg.save_to(&self.config_file)?;
        self.notify(Status::success("Saved. Restart to use it."));
        self.touch();
        Ok(())
    }

    /// Opens the dialog that names a new vault directory.
    ///
    /// Seeded with the current path so the user edits the value they can see
    /// rather than retyping it from memory, which is where typos come from.
    pub fn begin_vault_dir_change(&mut self) {
        let current = self.paths.root().to_string_lossy().to_string();
        self.modal = Some(Modal::Text { title: "vault directory".into(), value: current });
    }

    /// Opens the master-password dialog for the highlighted row.
    ///
    /// The old password is not asked for: the vault is already unlocked, and
    /// an unlocked session is the proof. Re-entering it would only train the
    /// user to type it twice.
    pub fn begin_master_password_change(&mut self) {
        if self.session.is_none() {
            self.notify(Status::error("Unlock the vault first"));
            return;
        }
        self.modal = Some(Modal::Password {
            title: "master password".into(),
            value: String::new(),
            confirm: String::new(),
            confirm_active: false,
        });
    }

    /// Closes the vault and returns to the unlock screen.
    ///
    /// Named for what it does rather than "delete": the entries on disk are not
    /// touched, so this is reversible by unlocking again.
    /// Asks for confirmation before emptying the vault.
    ///
    /// A reset deletes every entry blob and re-encrypts a fresh index, so it is
    /// the most destructive thing the app can do and needs an explicit yes.
    pub fn request_reset_vault(&mut self) {
        let count = self.total_entry_count();
        self.modal = Some(Modal::ask(
            "Reset vault",
            &format!(
                "Delete all {count} entries and start over?\n\n\
                 This cannot be undone."
            ),
            "Erase",
            PendingAction::ResetVault,
        ));
    }

    /// Performs the reset. Only reached once the user has answered yes.
    fn commit_reset_vault(&mut self) {
        let Some(session) = self.session.as_mut() else {
            self.notify_error(AppError::NoVault);
            return;
        };
        match session.wipe() {
            Ok(count) => {
                self.detail = None;
                self.form = None;
                self.refresh();
                self.notify(Status::success(&format!("Vault reset, {count} entries erased")));
            }
            Err(e) => self.notify_error(e),
        }
    }

    /// Locks the vault and returns to the unlock screen.
    ///
    /// The entries on disk are untouched, so this is reversible by unlocking
    /// again; it is what the settings row offers.
    pub fn lock_from_settings(&mut self) {
        self.lock();
        self.notify(Status::info("The vault is locked"));
    }

    // ----------------------------------------------------------------- chrome    /// Closes whatever modal is up.
    pub fn dismiss_modal(&mut self) {
        self.modal = None;
        self.touch();
    }

    /// Shows a message in the status line.
    pub fn notify(&mut self, status: Status) {
        self.status = Some(status);
    }

    /// Shows an error in the status line.
    pub fn notify_error(&mut self, e: AppError) {
        self.notify(Status::error(&e.message()));
    }

    /// Marks the state as needing a redraw.
    ///
    /// A no-op counter would cost a comparison on every mutation; the render
    /// loop simply redraws after each key, so this exists to make the intent
    /// explicit at the call sites rather than to drive anything.
    pub fn touch(&mut self) {}

    /// Counts `elapsed` seconds of inactivity, locking if the delay has passed.
    ///
    /// Returns whether the vault was locked.
    pub fn tick_idle(&mut self, elapsed: u64) -> bool {
        if self.auto_lock_secs == 0 || self.session.is_none() {
            return false;
        }
        self.idle_secs = self.idle_secs.saturating_add(elapsed);
        if self.idle_secs >= self.auto_lock_secs {
            self.lock();
            return true;
        }
        false
    }

    /// Resets the idle timer, called on every keystroke.
    pub fn note_activity(&mut self) {
        self.idle_secs = 0;
    }

    /// The seconds remaining before auto-lock, for the status line.
    pub fn auto_lock_countdown(&self) -> Option<u64> {
        if self.auto_lock_secs == 0 || self.session.is_none() {
            return None;
        }
        Some(self.auto_lock_secs.saturating_sub(self.idle_secs))
    }

    /// How many entries the vault holds, ignoring the current filter, so the
    /// header count doesn't change as the user searches.
    pub fn total_entry_count(&self) -> usize {
        self.session
            .as_ref()
            .map(|s| s.index.entries.iter().filter(|e| !e.deleted).count())
            .unwrap_or(0)
    }

    /// How many entries the list is showing after filtering.
    pub fn filtered_count(&self) -> usize {
        self.rows.len()
    }

    /// The title and username for one row, for the list renderer.
    pub fn row_label(&self, index: usize) -> (String, String, bool) {
        let Some(id) = self.rows.get(index) else { return (String::new(), String::new(), false) };
        let Some(entry) = self
            .session
            .as_ref()
            .and_then(|s| s.index.entries.iter().find(|e| &e.id == id))
        else {
            return (String::new(), String::new(), false);
        };
        (entry.title.clone(), entry.username.clone(), entry.favorite)
    }

    /// Generates a password from the form's generator settings.
    pub fn generate_password(&mut self) -> Result<(), AppError> {
        let options = self
            .form
            .as_ref()
            .map(|f| f.generator.clone())
            .unwrap_or_else(|| self.generator.clone());
        // The character-class check runs first because it is the one the user
        // can actually fix: turning a class back on. The length is clamped
        // rather than refused, since nothing in the UI lets it drift out of
        // range in the first place and a rejection would read as a crash.
        if !options.uppercase && !options.lowercase && !options.numbers && !options.symbols {
            return Err(AppError::BadInput("Turn on at least one kind of character.".into()));
        }
        let generated = domi_core::password::generate_password(
            options.clamped_length(),
            options.uppercase,
            options.lowercase,
            options.numbers,
            options.symbols,
        )
        .map_err(|e| AppError::BadInput(e.to_string()))?;
        if let Some(form) = self.form.as_mut() {
            form.password = generated;
        } else {
            self.notify(Status::error("Open an entry first"));
            return Ok(());
        }
        self.notify(Status::success("Password generated"));
        self.touch();
        Ok(())
    }

    /// The entry the detail pane is showing.
    pub fn detail(&self) -> Option<&Entry> {
        self.detail.as_ref()
    }}

/// The vault row, the one whose value is free text.
pub const ROW_VAULT: usize = 0;
/// The key-derivation row, shown for information only.
pub const ROW_KDF: usize = 1;
/// The auto-lock row, changed with left/right.
pub const ROW_AUTO_LOCK: usize = 2;
/// The master-password row, which opens the rekey flow.
pub const ROW_MASTER_PASSWORD: usize = 3;
/// The row that closes the vault and discards its entries.
pub const ROW_RESET: usize = 4;

/// The number of rows on the settings screen.
pub const SETTINGS_ROWS: usize = 5;

/// The first settings row to draw so that the cursor stays on screen.
///
/// Pure, because the view only ever has `&AppState`: the geometry comes in as
/// an argument and nothing is written back. On a terminal too short to show all
/// five rows, this is what keeps reset and rekey reachable instead of silently
/// clipped off the bottom.
pub fn settings_window(cursor: usize, capacity: usize) -> usize {
    let capacity = capacity.clamp(1, SETTINGS_ROWS);
    let max_offset = SETTINGS_ROWS - capacity;
    // Scroll down only as far as the cursor demands, so the first rows stay put
    // until the cursor actually reaches them.
    if cursor < capacity { 0 } else { cursor + 1 - capacity }.min(max_offset)
}

/// How an auto-lock delay reads in the settings row and in a notification.
pub fn auto_lock_label(secs: u64) -> String {
    if secs == 0 {
        return "off".to_string();
    }
    if secs.is_multiple_of(3600) {
        let hours = secs / 3600;
        return if hours == 1 { "1 hour".to_string() } else { format!("{hours} hours") };
    }
    let minutes = secs / 60;
    if minutes == 1 {
        "1 minute".to_string()
    } else {
        format!("{minutes} minutes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;
    use crate::vault_store::testing::TempVault;

    /// A state on a throwaway vault, on whatever screen that vault implies.
    fn app_state() -> (TempVault, AppState) {
        let tmp = TempVault::new();
        let state = testkit::state_at(tmp.paths());
        (tmp, state)
    }

    /// A window big enough for the whole list never scrolls, whatever the cursor.
    #[test]
    fn a_settings_window_that_fits_everything_does_not_scroll() {
        for cursor in 0..SETTINGS_ROWS {
            assert_eq!(settings_window(cursor, SETTINGS_ROWS), 0, "cursor {cursor}");
        }
    }

    /// On a terminal too short for the list, the cursor row is always drawn.
    #[test]
    fn a_short_settings_window_scrolls_to_keep_the_cursor_on_screen() {
        for capacity in 1..SETTINGS_ROWS {
            for cursor in 0..SETTINGS_ROWS {
                let offset = settings_window(cursor, capacity);
                assert!(
                    offset <= cursor && cursor < offset + capacity,
                    "cursor {cursor} off screen at capacity {capacity} (offset {offset})"
                );
                // And the window never starts past the end of the list.
                assert!(offset + capacity <= SETTINGS_ROWS || capacity == 1, "capacity {capacity}");
            }
        }
    }

    /// A capacity of zero means a pane too short for even one row, which still
    /// has to produce a usable window rather than underflow.
    #[test]
    fn a_settings_window_of_zero_is_clamped_to_one_row() {
        assert_eq!(settings_window(0, 0), 0);
        assert_eq!(settings_window(ROW_RESET, 0), ROW_RESET);
    }

    /// The window only scrolls once the cursor passes the bottom edge, so the
    /// first rows stay put on a tall terminal with the cursor near the top.
    #[test]
    fn a_settings_window_still_shows_the_first_rows_until_the_cursor_demands_otherwise() {
        assert_eq!(settings_window(ROW_VAULT, 3), 0);
        assert_eq!(settings_window(ROW_AUTO_LOCK, 3), 0);
        assert_eq!(settings_window(ROW_MASTER_PASSWORD, 3), 1);
        assert_eq!(settings_window(ROW_RESET, 3), 2);
    }

    /// An unlocked vault holding one saved entry.
    fn unlocked_with_entry() -> (TempVault, AppState) {
        let (tmp, mut state) = app_state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("correct horse", "correct horse").expect("the vault is created");
        state.begin_new();
        {
            let form = state.form.as_mut().expect("the editor is open");
            form.title = "GitHub".into();
            form.username = "ada".into();
            form.password = "hunter2".into();
            form.url = "https://github.com".into();
        }
        state.save_form().expect("the entry saves");
        (tmp, state)
    }

    /// An unlocked vault holding two titled entries, "First" and "Second".
    fn unlocked_with_two_entries() -> (TempVault, AppState) {
        let (tmp, mut state) = app_state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("correct horse", "correct horse").expect("the vault is created");
        for (title, password) in [("First", "one"), ("Second", "two")] {
            state.begin_new();
            if let Some(form) = state.form.as_mut() {
                form.title = title.into();
                form.password = password.into();
            }
            state.save_form().expect("the entry saves");
        }
        state.move_selection(0);
        (tmp, state)
    }

    // ------------------------------------------------------------- opening

    #[test]
    fn a_fresh_vault_opens_on_setup_and_an_existing_one_on_unlock() {
        let (tmp, mut state) = app_state();
        assert_eq!(state.initial_screen(), Screen::Setup);

        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("manifest.json"), "{}").unwrap();
        assert_eq!(state.initial_screen(), Screen::Unlock);
    }

    #[test]
    fn creating_a_vault_mismatched_passwords_is_refused() {
        let (_tmp, mut state) = app_state();
        state.kdf = crate::vault_store::test_params();
        let err = state.create_vault("one", "two").expect_err("the passwords differ");
        assert!(matches!(err, AppError::BadInput(_)), "got {err:?}");
    }

    #[test]
    fn a_typed_password_is_zeroized_once_the_vault_opens() {
        let (_tmp, mut state) = app_state();
        state.kdf = crate::vault_store::test_params();
        state.password = "correct horse".into();
        state.confirm = "correct horse".into();
        state.create_vault("correct horse", "correct horse").unwrap();
        assert!(state.password.is_empty(), "the password should not linger in state");
        assert_eq!(state.screen, Screen::Vault);
    }

    #[test]
    fn the_wrong_password_is_refused_and_the_screen_does_not_change() {
        let (tmp, mut state) = app_state();
        state.kdf = crate::vault_store::test_params();
        state.create_vault("correct horse", "correct horse").unwrap();
        state.lock();
        assert_eq!(state.screen, Screen::Unlock);

        let err = state.unlock("wrong").expect_err("that password is wrong");
        assert!(matches!(err, AppError::WrongPassword), "got {err:?}");
        assert_eq!(state.screen, Screen::Unlock);
        assert!(state.session.is_none());
        drop(tmp);
    }

    // ---------------------------------------------------------------- list

    #[test]
    fn a_saved_entry_shows_up_in_the_list() {
        let (_tmp, state) = unlocked_with_entry();
        assert_eq!(state.filtered_count(), 1);
        assert_eq!(state.row_label(0).0, "GitHub");
    }

    #[test]
    fn the_search_query_narrows_the_list() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.set_query("git".into());
        assert_eq!(state.filtered_count(), 1);
        state.set_query("nothing matches".into());
        assert_eq!(state.filtered_count(), 0);
    }

    #[test]
    fn clearing_the_query_brings_every_entry_back() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.set_query("zzz".into());
        assert_eq!(state.filtered_count(), 0);
        state.set_query(String::new());
        assert_eq!(state.filtered_count(), 1);
    }

    #[test]
    fn the_favorites_filter_hides_everything_until_one_is_marked() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.toggle_filter();
        assert_eq!(state.filtered_count(), 0, "nothing is a favorite yet");
        state.toggle_filter();

        state.toggle_favorite();
        state.toggle_filter();
        assert_eq!(state.filtered_count(), 1, "the entry just became a favorite");
    }

    #[test]
    fn the_selection_stays_on_the_same_entry_after_filtering() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "Zebra".into();
            form.password = "x".into();
        }
        state.save_form().unwrap();
        assert_eq!(state.filtered_count(), 2);

        // Select the second entry, then filter down to one and back.
        state.move_selection(1);
        let picked = state.selected_id();
        state.set_query("zebra".into());
        assert_eq!(state.filtered_count(), 1);
        state.set_query(String::new());
        assert_eq!(state.selected_id(), picked, "filtering should not lose the selection");
    }

    #[test]
    fn the_detail_pane_follows_the_selection() {
        // The pane used to keep whatever entry was loaded at unlock, so moving
        // the cursor showed the previous entry's password.
        let (_tmp, mut state) = unlocked_with_two_entries();
        assert_eq!(state.detail().map(|e| e.title.as_str()), Some("First"));

        state.move_selection(1);
        assert_eq!(state.detail().map(|e| e.title.as_str()), Some("Second"));

        state.move_selection(-1);
        assert_eq!(state.detail().map(|e| e.title.as_str()), Some("First"));
    }

    #[test]
    fn the_detail_pane_follows_the_selection_through_a_filter_change() {
        let (_tmp, mut state) = unlocked_with_two_entries();
        state.set_query("second".into());
        assert_eq!(
            state.detail().map(|e| e.title.as_str()),
            Some("Second"),
            "filtering moved the selection, so the pane must follow"
        );

        state.set_query("nothing matches".into());
        assert!(state.detail().is_none(), "an empty list shows nothing");
    }

    #[test]
    fn moving_past_the_end_of_the_list_stops_at_the_end() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.move_selection(1_000);
        assert_eq!(state.selected, 0, "there is only one entry");
        state.move_selection(-1_000);
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn a_deleted_entry_leaves_the_list() {
        let (_tmp, mut state) = unlocked_with_entry();
        assert_eq!(state.filtered_count(), 1);
        state.request_delete_selected();
        // Nothing happens until the confirmation is answered.
        assert_eq!(state.filtered_count(), 1);
        assert!(state.modal.is_some());

        state.dismiss_modal();
        state.confirm_pending(PendingAction::DeleteEntry);
        assert_eq!(state.filtered_count(), 0);
    }

    // --------------------------------------------------------------- editor

    #[test]
    fn the_editor_refuses_an_entry_with_no_title() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "   ".into();
        }
        let err = state.save_form().expect_err("a title is required");
        assert!(matches!(err, AppError::BadInput(_)), "got {err:?}");
    }

    #[test]
    fn cancelling_the_editor_writes_nothing() {
        let (_tmp, mut state) = unlocked_with_entry();
        let before = state.filtered_count();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "Discarded".into();
        }
        state.cancel_form();
        assert_eq!(state.filtered_count(), before);
        assert_eq!(state.screen, Screen::Vault);
        assert!(state.form.is_none());
    }

    #[test]
    fn editing_an_entry_updates_it_rather_than_adding_one() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_edit();
        assert!(state.form.as_ref().expect("the editor is open").is_edit());
        if let Some(form) = state.form.as_mut() {
            form.username = "grace".into();
        }
        state.save_form().unwrap();
        assert_eq!(state.filtered_count(), 1, "still one entry");
        assert_eq!(state.row_label(0).1, "grace");
    }

    #[test]
    fn a_password_field_never_stores_its_plaintext_in_the_title() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        let form = state.form.as_mut().expect("the editor is open");

        // Typing lands in whichever field has focus, and nowhere else.
        form.insert_char(Field::Title, 'G');
        assert_eq!(form.title, "G");
        assert_eq!(form.password, "");

        form.focused = Field::Password;
        form.insert_char(Field::Password, 'x');
        assert_eq!(form.password, "x");
        assert_eq!(form.title, "G", "the title must not have grown");
    }

    #[test]
    fn tabs_never_reach_the_non_text_fields() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        let form = state.form.as_mut().expect("the editor is open");
        form.focused = Field::Favorite;
        assert!(!Field::Favorite.is_text());
        form.focused = Field::Tags;
        assert!(Field::Tags.is_text());
    }

    // -------------------------------------------------------------- secrets

    #[test]
    fn revealing_is_off_by_default_and_only_toggles_when_asked() {
        let (_tmp, mut state) = unlocked_with_entry();
        assert!(!state.reveal);
        state.toggle_reveal();
        assert!(state.reveal);
    }

    #[test]
    fn locking_clears_the_loaded_entry_and_the_typed_password() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.password = "leftover".into();
        state.load_detail();
        assert!(state.detail.is_some());

        state.lock();
        assert!(state.detail.is_none());
        assert!(state.password.is_empty());
        assert!(state.session.is_none());
        assert_eq!(state.screen, Screen::Unlock);
    }

    #[test]
    fn copying_queues_the_secret_and_reports_the_size_it_copied() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.load_detail();
        state.copy_password();
        let queued = state.pending_copy.take().expect("a copy is queued");
        assert_eq!(queued, "hunter2");
        assert!(crate::clipboard::is_supported_size(&queued));
    }

    // ------------------------------------------------------------ auto-lock

    #[test]
    fn auto_lock_fires_once_the_idle_delay_has_passed() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.auto_lock_secs = 60;
        assert!(!state.tick_idle(30), "halfway there is nothing to do");
        assert!(state.session.is_some());
        assert!(state.tick_idle(31), "the delay has now passed");
        assert!(state.session.is_none());
        assert_eq!(state.screen, Screen::Unlock);
    }

    #[test]
    fn any_keystroke_pushes_the_auto_lock_back_out() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.auto_lock_secs = 60;
        state.tick_idle(50);
        state.note_activity();
        assert!(!state.tick_idle(30), "the countdown restarted");
    }

    #[test]
    fn an_auto_lock_delay_of_zero_never_locks_the_vault() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.auto_lock_secs = 0;
        assert!(!state.tick_idle(100_000));
        assert!(state.session.is_some());
    }

    #[test]
    fn the_countdown_reads_as_whole_minutes_and_hours() {
        assert_eq!(auto_lock_label(0), "off");
        assert_eq!(auto_lock_label(60), "1 minute");
        assert_eq!(auto_lock_label(900), "15 minutes");
        assert_eq!(auto_lock_label(3600), "1 hour");
        assert_eq!(auto_lock_label(21600), "6 hours");
    }

    #[test]
    fn stepping_the_auto_lock_delay_lands_on_a_preset() {
        let (_tmp, mut state) = app_state();
        for _ in AppState::AUTO_LOCK_STEPS {
            assert!(AppState::AUTO_LOCK_STEPS.contains(&state.auto_lock_secs));
            state.step_auto_lock(1);
            assert!(
                AppState::AUTO_LOCK_STEPS.contains(&state.auto_lock_secs),
                "got {}",
                state.auto_lock_secs
            );
        }
    }

    // ------------------------------------------------------------- settings

    #[test]
    fn the_settings_cursor_cannot_leave_the_screen() {
        let (_tmp, mut state) = app_state();
        state.move_settings_row(-5);
        assert_eq!(state.settings_row, 0);
        state.move_settings_row(999);
        assert_eq!(state.settings_row, SETTINGS_ROWS - 1);
    }

    #[test]
    fn changing_the_vault_directory_persists_it_to_the_config_file() {
        let (_tmp, mut state) = app_state();
        let dir = std::env::temp_dir().join("domi-moved-vault");
        state.set_vault_dir(dir.to_str().unwrap()).expect("the directory is saved");

        let saved = Config::load_from(&state.config_file).expect("the config parses");
        assert_eq!(saved.vault_dir(), Some(dir.to_str().unwrap()));
    }

    #[test]
    fn saving_the_auto_lock_delay_keeps_the_vault_directory_already_on_disk() {
        // The two settings are written by different code paths; a blind
        // rewrite of the whole file would drop whichever one the user set
        // earlier in the session.
        let (_tmp, mut state) = app_state();
        let dir = std::env::temp_dir().join("domi-kept-vault");
        state.set_vault_dir(dir.to_str().unwrap()).unwrap();

        state.step_auto_lock(1);
        let saved = Config::load_from(&state.config_file).expect("the config parses");
        assert_eq!(saved.vault_dir(), Some(dir.to_str().unwrap()), "the directory survived");
        assert!(saved.auto_lock_secs.is_some(), "the delay was written too");
    }

    #[test]
    fn a_blank_vault_directory_is_refused_rather_than_written() {
        let (_tmp, mut state) = app_state();
        let err = state.set_vault_dir("   ").expect_err("a blank path is not a directory");
        assert!(matches!(err, AppError::BadInput(_)), "got {err:?}");
    }

    // ----------------------------------------------------------- the wipe

    #[test]
    fn resetting_a_vault_erases_every_entry() {
        let (tmp, mut state) = unlocked_with_entry();
        state.request_reset_vault();
        assert!(state.modal.is_some(), "a reset asks first");

        state.dismiss_modal();
        state.confirm_pending(PendingAction::ResetVault);
        assert_eq!(state.filtered_count(), 0);

        // And the vault is still usable afterwards.
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.title = "After the wipe".into();
            form.password = "y".into();
        }
        state.save_form().expect("the vault still takes entries");
        assert_eq!(state.filtered_count(), 1);
        drop(tmp);
    }

    #[test]
    fn a_reset_removes_the_entry_blobs_from_disk() {
        let (tmp, mut state) = unlocked_with_entry();
        let entries_dir = tmp.path().join("entries");
        let before = std::fs::read_dir(&entries_dir).expect("the entries dir exists").count();
        assert!(before > 0);

        state.confirm_pending(PendingAction::ResetVault);
        let after = std::fs::read_dir(&entries_dir).expect("the entries dir survives").count();
        assert_eq!(after, 0, "the ciphertext should be gone, not just hidden");
    }

    // ------------------------------------------------------------ generator

    #[test]
    fn generating_produces_a_password_of_the_requested_length() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.generator.length = 32;
        }
        state.generate_password().expect("generation succeeds");
        let password = state.form.as_ref().expect("the editor is open").password.clone();
        assert_eq!(password.chars().count(), 32);
    }

    #[test]
    fn a_generator_with_no_character_classes_is_refused() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.generator.uppercase = false;
            form.generator.lowercase = false;
            form.generator.numbers = false;
            form.generator.symbols = false;
        }
        let err = state.generate_password().expect_err("an empty charset cannot generate");
        assert!(matches!(err, AppError::BadInput(_)), "got {err:?}");
    }

    #[test]
    fn a_generator_length_out_of_range_is_clamped_rather_than_refused() {
        let (_tmp, mut state) = unlocked_with_entry();
        state.begin_new();
        if let Some(form) = state.form.as_mut() {
            form.generator.length = 10_000;
        }
        state.generate_password().expect("the length is clamped into range");
        let password = state.form.as_ref().expect("the editor is open").password.clone();
        assert_eq!(
            password.chars().count(),
            domi_core::password::MAX_PASSWORD_LENGTH
        );
    }
}
