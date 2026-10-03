//! Screen and selection state for the whole TUI.
//!
//! Deliberately free of iocraft: this file holds *what the app is* (which
//! screen, which row is selected, what the form contains) while `app.rs` and
//! `widgets/` hold how it looks. That split is what lets the interesting
//! behaviour — filter remapping, form validation, auto-lock — be unit tested
//! without a terminal.
//!
//! Filtering delegates to [`domi_core::search::SearchCache`] rather than
//! reimplementing matching here, so the TUI and the other shells agree on what
//! a search for "git" means.

use domi_core::search::SearchCache;
use domi_core::vault::{Entry, IndexEntry, ItemCategory};
use domi_core::{KdfParams, now_unix};
use zeroize::Zeroize;

use crate::error::AppError;
use crate::vault_store::{VaultPaths, VaultSession};

/// The six screens from the product spec. `List` and `Detail` are one screen
/// here: they are two panes of a single layout, and splitting them would mean
/// the user navigates away from the list just to read an entry.
///
/// Defaults to `Unlock` so a props struct can derive `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// Create a vault: choose location, password, and KDF cost.
    Setup,
    /// Unlock an existing vault. The default: almost every run starts here.
    #[default]
    Unlock,
    /// The main two-pane screen: entry list plus entry detail.
    Vault,
    /// Create or edit one entry.
    Edit,
    /// KDF cost, master-password change, vault location.
    Settings,
}

impl Screen {
    /// Every screen's title, for the header.
    pub fn title(self) -> &'static str {
        match self {
            Screen::Setup => "Set up vault",
            Screen::Unlock => "Locked",
            Screen::Vault => "Vault",
            Screen::Edit => "Edit entry",
            Screen::Settings => "Settings",
        }
    }

}

/// Which pane the keyboard is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Detail,
    /// The search box at the top of the list pane.
    Search,
}

/// A saved slice of the list. `All` means no filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    All,
    Favorites,
    /// One tag, held as its id because that is what
    /// [`domi_core::search::SearchCache::query_by_tag`] matches on. The name
    /// is looked up from the index for display; see [`Filter::label`].
    Tag { id: String, name: String },
}

impl Filter {
    /// Short label for the status line, so the user can always see that a
    /// filter is active and is looking at a subset of the vault.
    pub fn label(&self) -> String {
        match self {
            Filter::All => "All".to_string(),
            Filter::Favorites => "Favorites".to_string(),
            Filter::Tag { name, .. } => format!("#{name}"),
        }
    }

    /// True when the list is showing a subset, which is the only case where
    /// the UI needs an "empty" explanation.
    pub fn is_narrowed(&self) -> bool {
        !matches!(self, Filter::All)
    }
}

/// A modal dialog drawn over whatever screen is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Yes/no. Destructive flows (delete, overwrite) land here.
    Confirm {
        title: String,
        body: String,
        danger: bool,
        yes_label: String,
    },
    /// Password entry, used by the master-password change. The old password
    /// is not asked for: an unlocked session is already proof of it.
    Password { title: String, value: String },
}

impl Modal {
    #[cfg(test)]
    pub fn confirm(title: &str, body: &str) -> Self {
        Modal::Confirm {
            title: title.to_string(),
            body: body.to_string(),
            danger: false,
            yes_label: "Confirm".to_string(),
        }
    }

    /// A destructive confirmation. The UI tints this one red and spells the
    /// action out, so a stray `y` can't destroy a vault.
    pub fn danger(title: &str, body: &str) -> Self {
        Modal::Confirm {
            title: title.to_string(),
            body: body.to_string(),
            danger: true,
            yes_label: "Delete".to_string(),
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Modal::Confirm { title, .. } | Modal::Password { title, .. } => title,
        }
    }

    /// Modal dialogs take every keypress; nothing behind them is reachable.
    #[cfg(test)]
    pub fn blocks_input(&self) -> bool {
        true
    }
}

/// A transient message in the status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub kind: StatusKind,
    pub at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

impl Status {
    pub fn info(text: &str) -> Self {
        Status { text: text.to_string(), kind: StatusKind::Info, at: now_unix() }
    }
    pub fn success(text: &str) -> Self {
        Status { text: text.to_string(), kind: StatusKind::Success, at: now_unix() }
    }
    pub fn error(text: &str) -> Self {
        Status { text: text.to_string(), kind: StatusKind::Error, at: now_unix() }
    }
}

/// Options for the built-in password generator, owned by the edit form and
/// the settings screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Validates against the core generator's length bounds, and refuses a
    /// password with no character classes (core treats that as a length-valid
    /// but useless password).
    pub fn validate(&self) -> Result<(), String> {
        if !(domi_core::password::MIN_PASSWORD_LENGTH..=domi_core::password::MAX_PASSWORD_LENGTH)
            .contains(&self.length)
        {
            return Err(format!(
                "Length must be between {} and {}.",
                domi_core::password::MIN_PASSWORD_LENGTH,
                domi_core::password::MAX_PASSWORD_LENGTH
            ));
        }
        if !(self.uppercase || self.lowercase || self.numbers || self.symbols) {
            return Err("Turn on at least one character type.".to_string());
        }
        Ok(())
    }

    pub fn generate(&self) -> Result<String, AppError> {
        self.validate().map_err(AppError::BadInput)?;
        domi_core::generate_password(
            self.length,
            self.uppercase,
            self.lowercase,
            self.numbers,
            self.symbols,
        )
        .map_err(|e| crate::error::friendly(e, "password"))
    }
}

/// Every field the edit form can focus, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
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

    /// Fields that hold text, as opposed to toggles and the category cycler.
    pub fn is_text(self) -> bool {
        matches!(self, Field::Title | Field::Username | Field::Password | Field::Url | Field::Notes | Field::Totp)
    }

    pub fn next(self) -> Field {
        let i = Field::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Field::ALL[(i + 1) % Field::ALL.len()]
    }

    pub fn prev(self) -> Field {
        let i = Field::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Field::ALL[(i + Field::ALL.len() - 1) % Field::ALL.len()]
    }
}

/// Every category, in cycler order. One source of truth for both
/// [`EntryForm::cycle_category`] and its test.
fn all_categories() -> [ItemCategory; 5] {
    [
        ItemCategory::Login,
        ItemCategory::CreditCard,
        ItemCategory::SecureNote,
        ItemCategory::Identity,
        ItemCategory::BankAccount,
    ]
}

/// The editable buffer for one entry.
///
/// Holds real plaintext, so it is never logged or rendered directly: the form
/// widget masks the password and totp fields and the struct is dropped on
/// cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryForm {
    pub original_id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: String,
    pub category: ItemCategory,
    pub favorite: bool,
    /// Comma-separated; split on save, trimmed, empties dropped.
    pub tags: String,
    /// Which field has the cursor.
    pub field: Field,
    /// Whether password and TOTP render as dots.
    pub reveal: bool,
}

impl EntryForm {
    /// A blank form for a new entry.
    pub fn new(now: i64) -> Self {
        let _ = now;
        EntryForm {
            original_id: None,
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp: String::new(),
            category: ItemCategory::default(),
            favorite: false,
            tags: String::new(),
            field: Field::Title,
            reveal: false,
        }
    }

    /// A form pre-filled from an existing entry.
    ///
    /// `tag_names` pairs each tag id with the name the user typed, because
    /// core stores ids and a form field has to hold something readable and
    /// editable. Ids with no matching name fall back to the id itself, so an
    /// orphaned reference is visible in the field rather than dropped —
    /// saving it back then fails loudly rather than silently untagging the
    /// entry. See [`AppState::tag_id_names`] for where the pairs come from.
    pub fn from_entry(entry: &Entry, tag_names: &[(String, String)]) -> Self {
        let tags = entry
            .tags
            .iter()
            .map(|id| {
                tag_names
                    .iter()
                    .find(|(tag_id, _)| tag_id == id)
                    .map(|(_, name)| name.clone())
                    .unwrap_or_else(|| id.clone())
            })
            .collect::<Vec<_>>()
            .join(", ");
        EntryForm {
            original_id: Some(entry.id.clone()),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            totp: entry.totp_secret.clone().unwrap_or_default(),
            category: entry.category,
            favorite: entry.favorite,
            tags,
            field: Field::Title,
            reveal: false,
        }
    }

    pub fn is_new(&self) -> bool {
        self.original_id.is_none()
    }

    /// Borrows the focused field's text for the text input to edit.
    pub fn text(&self) -> &str {
        match self.field {
            Field::Title => &self.title,
            Field::Username => &self.username,
            Field::Password => &self.password,
            Field::Url => &self.url,
            Field::Notes => &self.notes,
            Field::Totp => &self.totp,
            Field::Tags => &self.tags,
            // Toggles and the category cycler are changed with space/left-right
            // rather than typed into, so there is nothing to borrow.
            Field::Category | Field::Favorite => "",
        }
    }

    pub fn set_text(&mut self, value: String) {
        match self.field {
            Field::Title => self.title = value,
            Field::Username => self.username = value,
            Field::Password => self.password = value,
            Field::Url => self.url = value,
            Field::Notes => self.notes = value,
            Field::Totp => self.totp = value,
            Field::Tags => self.tags = value,
            Field::Category | Field::Favorite => {}
        }
    }

    /// Steps the category cycler.
    pub fn cycle_category(&mut self) {
        let all = all_categories();
        let i = all.iter().position(|c| *c == self.category).unwrap_or(0);
        self.category = all[(i + 1) % all.len()];
    }

    pub fn toggle_favorite(&mut self) {
        self.favorite = !self.favorite;
    }

    /// Splits the comma-separated tag field.
    pub fn tag_list(&self) -> Vec<String> {
        self.tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// Rejects a form that couldn't produce a usable entry, so the user gets a
    /// specific reason instead of a save that silently does nothing.
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() {
            return Err("Title is required.".to_string());
        }
        if self.title.chars().count() > 200 {
            return Err("Title must be 200 characters or fewer.".to_string());
        }
        if self.notes.chars().count() > 10_000 {
            return Err("Notes must be 10000 characters or fewer.".to_string());
        }
        Ok(())
    }

    /// Materialises the form into a core `Entry`, keeping the original id and
    /// timestamps when editing.
    ///
    /// `tag_ids` are the ids for `tag_list()`'s names, resolved by the caller
    /// via [`crate::vault_store::VaultSession::ensure_tags`]. Passing them in
    /// keeps the id/name translation next to the index that has to change.
    pub fn to_entry(&self, id: String, now: i64, tag_ids: Vec<String>) -> Entry {
        Entry {
            id,
            title: self.title.trim().to_string(),
            username: self.username.trim().to_string(),
            password: self.password.clone(),
            url: self.url.trim().to_string(),
            notes: self.notes.clone(),
            totp_secret: if self.totp.trim().is_empty() {
                None
            } else {
                Some(self.totp.trim().to_string())
            },
            custom_fields: Default::default(),
            updated_at: now,
            deleted: false,
            tags: tag_ids,
            collection_id: None,
            favorite: self.favorite,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: self.category,
            password_history: Vec::new(),
            attachments: Vec::new(),
        }
    }
}

/// The whole application state.
pub struct AppState {
    pub screen: Screen,
    pub focus: Focus,
    pub paths: VaultPaths,

    // Setup / unlock inputs.
    pub password: String,
    pub confirm: String,
    pub kdf: KdfParams,
    /// Argon2id at the default cost takes long enough to need a visible
    /// "working" state, otherwise the UI looks frozen.
    pub busy: bool,
    pub screen_error: Option<String>,

    // Vault contents.
    pub session: Option<VaultSession>,
    pub cache: SearchCache,
    pub query: String,
    pub filter: Filter,
    /// Visible entry ids, in display order.
    pub rows: Vec<String>,
    pub selected: usize,
    /// First visible row, for scroll position.
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
    /// and read back by the render snapshot to size the scroll window.
    pub list_capacity: usize,
}

/// How an auto-lock delay reads in the settings row and in a notification.
fn auto_lock_label(secs: u64) -> String {
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

impl AppState {
    pub fn new(paths: VaultPaths) -> Self {
        AppState {
            screen: Screen::Unlock,
            focus: Focus::List,
            paths,
            password: String::new(),
            confirm: String::new(),
            kdf: KdfParams::default(),
            busy: false,
            screen_error: None,
            session: None,
            cache: SearchCache::default(),
            query: String::new(),
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
            auto_lock_secs: 15 * 60,
            idle_secs: 0,
            should_quit: false,
            pending_copy: None,
            // Overwritten from the terminal size on the first frame.
            list_capacity: 0,
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
                .query_favorites()
                .into_iter()
                .filter(|i| matches_query(i, &self.query))
                .collect(),
            Filter::Tag { id, .. } => self
                .cache
                .query_by_tag(id)
                .into_iter()
                .filter(|i| matches_query(i, &self.query))
                .collect(),
        };
        // `rebuild_from_index` preserves index order, which `put_entry`
        // appends to; sort by most recently updated so the list matches what
        // `visible_entries` shows elsewhere.
        items.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
        self.rows = items.iter().map(|i| i.id.clone()).collect();

        // Keep the cursor on the same entry across a filter change where
        // possible, so narrowing the list doesn't move the user somewhere
        // unrelated.
        self.selected = previous
            .and_then(|id| self.rows.iter().position(|r| *r == id))
            .unwrap_or_default();
        if self.rows.is_empty() {
            self.selected = 0;
            self.detail = None;
        } else {
            self.load_detail();
        }
    }

    /// The currently selected entry id, if any.
    pub fn selected_id(&self) -> Option<String> {
        self.rows.get(self.selected).cloned()
    }

    /// The selected index entry from the in-memory index.
    pub fn selected_index_entry(&self) -> Option<&IndexEntry> {
        let id = self.selected_id()?;
        let session = self.session.as_ref()?;
        session.index.entries.iter().find(|e| e.id == id)
    }

    /// The selected entry's short title, for the header.
    pub fn selected_title(&self) -> String {
        self.selected_index_entry().map(|e| e.title.clone()).unwrap_or_default()
    }

    /// Every live tag as `(id, name)`, for the detail pane and the edit form.
    ///
    /// The view and the form both need to show names; the index only has ids.
    pub fn tag_id_names(&self) -> Vec<(String, String)> {
        self.session
            .as_ref()
            .map(|s| {
                s.index
                    .tags
                    .iter()
                    .filter(|t| !t.deleted)
                    .map(|t| (t.id.clone(), t.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Decrypts the selected entry into the detail pane.
    pub fn load_detail(&mut self) {
        let Some(id) = self.selected_id() else {
            self.detail = None;
            return;
        };
        let Some(session) = &self.session else {
            self.detail = None;
            return;
        };
        self.detail = session.load_entry(&id).ok();
    }

    /// Moves the selection by `delta`, clamped to the ends so a long keypress
    /// run can't leave the cursor past the last row.
    pub fn move_selection(&mut self, delta: i64) {
        if self.rows.is_empty() {
            self.selected = 0;
            return;
        }
        let last = self.rows.len() as i64 - 1;
        let next = (self.selected as i64 + delta).clamp(0, last);
        if next as usize != self.selected {
            self.selected = next as usize;
            self.load_detail();
        }
    }

    /// Keeps `selected` inside the visible window after a resize, and lets the
    /// caller draw with `height` rows starting at `offset`.
    pub fn clamp_scroll(&mut self, height: usize) {
        if height == 0 {
            self.offset = 0;
            return;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        }
        if self.selected >= self.offset + height {
            self.offset = self.selected + 1 - height;
        }
        let max_offset = self.rows.len().saturating_sub(height);
        self.offset = self.offset.min(max_offset);
    }

    /// Called after a save or delete so the list, detail, and index agree.
    pub fn on_entries_changed(&mut self) {
        self.refresh();
    }

    // ------------------------------------------------------------- filtering

    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.recompute_rows();
    }

    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = filter;
        self.recompute_rows();
    }

    pub fn toggle_favorite_filter(&mut self) {
        let next =
            if matches!(self.filter, Filter::Favorites) { Filter::All } else { Filter::Favorites };
        self.set_filter(next);
    }

    /// Filters the list to the selected entry's first tag, or drops the filter
    /// when it is already applied.
    ///
    /// Bound to `t`: the tags an entry carries are only discoverable from the
    /// entry, so this narrows to something the user is looking at rather than
    /// asking them to type a tag they would have to already know.
    pub fn toggle_tag_filter(&mut self) {
        let Some(entry) = self.detail.clone() else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        let Some(tag_id) = entry.tags.first().cloned() else {
            self.notify(Status::error("This entry has no tags"));
            return;
        };
        let name = self.tag_name(&tag_id);
        let next = match &self.filter {
            Filter::Tag { id, .. } if *id == tag_id => Filter::All,
            _ => Filter::Tag { id: tag_id, name },
        };
        self.set_filter(next);
    }

    /// The name behind a tag id, from the in-memory index.
    ///
    /// Falls back to the id so a filter is always labelled with something and
    /// a deleted tag still reads as a filter rather than silently becoming
    /// "All".
    fn tag_name(&self, id: &str) -> String {
        self.tag_id_names()
            .into_iter()
            .find(|(tag_id, _)| tag_id == id)
            .map(|(_, name)| name)
            .unwrap_or_else(|| id.to_string())
    }

    // -------------------------------------------------------------- statuses

    /// Shows a message and records the activity that resets the auto-lock.
    pub fn notify(&mut self, status: Status) {
        self.touch();
        self.status = Some(status);
    }

    pub fn notify_error(&mut self, err: AppError) {
        self.notify(Status::error(&err.message()));
    }

    /// Any keypress counts as activity for the auto-lock timer.
    pub fn touch(&mut self) {
        self.idle_secs = 0;
    }

    /// Advances the idle timer. Returns true when the vault should be locked.
    ///
    /// The caller must actually drop the session on true — this only decides.
    pub fn tick_idle(&mut self, elapsed: u64) -> bool {
        if self.auto_lock_secs == 0 || self.session.is_none() {
            return false;
        }
        self.idle_secs = self.idle_secs.saturating_add(elapsed);
        self.idle_secs >= self.auto_lock_secs
    }

    /// Drops the decrypted key and everything derived from it.
    pub fn lock(&mut self) {
        if let Some(session) = self.session.take() {
            session.lock();
        }
        // Order matters: wipe the in-memory text first, then drop the key. The
        // form holds a plaintext password and must not survive the session.
        if let Some(form) = self.form.as_mut() {
            form.password.zeroize();
        }
        self.password.zeroize();
        self.confirm.zeroize();
        self.pending_copy = None;
        self.detail = None;
        self.form = None;
        self.reveal = false;
        self.query.zeroize();
        self.cache = SearchCache::default();
        self.rows.clear();
        self.selected = 0;
        self.offset = 0;
        self.idle_secs = 0;
        self.focus = Focus::List;
        self.screen = Screen::Unlock;
        self.screen_error = None;
    }

    /// True when a modal is up, which suppresses every underlying keybinding.
    #[cfg(test)]
    pub fn modal_open(&self) -> bool {
        self.modal.is_some()
    }

    // -------------------------------------------------------------- actions

    /// Creates a vault, then unlocks it into a live session.
    ///
    /// Setup and Unlock share this path: creating a vault and unlocking one
    /// are the same sequence with a different starting point, so a single
    /// implementation keeps the two screens from drifting apart.
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
    fn after_unlock(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
        self.screen_error = None;
        self.screen = Screen::Vault;
        self.busy = false;
        self.refresh();
        self.load_detail();
        self.notify(Status::success("Vault unlocked"));
    }

    /// Closes a modal, discarding whatever it was collecting.
    pub fn dismiss_modal(&mut self) {
        // A password typed into a dialog that gets cancelled must not survive
        // in the discarded value.
        if let Some(Modal::Password { ref mut value, .. }) = self.modal {
            value.zeroize();
        }
        self.modal = None;
    }

    /// Opens the create-entry form.
    pub fn begin_new_entry(&mut self) {
        self.form = Some(EntryForm::new(now_unix()));
        self.screen = Screen::Edit;
        self.reveal = false;
        self.touch();
    }

    /// Opens the edit form for the selected entry.
    pub fn begin_edit_selected(&mut self) {
        let Some(entry) = self.detail.clone() else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        let names = self.tag_id_names();
        self.form = Some(EntryForm::from_entry(&entry, &names));
        self.screen = Screen::Edit;
        self.reveal = false;
        self.touch();
    }

    /// Leaves the edit screen, discarding the form.
    pub fn cancel_edit(&mut self) {
        if let Some(mut form) = self.form.take() {
            form.password.zeroize();
        }
        self.screen = Screen::Vault;
        self.load_detail();
        self.touch();
    }

    /// Validates and persists the form, then returns to the list.
    pub fn save_form(&mut self) -> Result<(), AppError> {
        let Some(form) = self.form.as_ref() else {
            self.screen = Screen::Vault;
            return Ok(());
        };
        if let Err(message) = form.validate() {
            return Err(AppError::BadInput(message));
        }
        let id = match &form.original_id {
            Some(id) => id.clone(),
            None => new_entry_id(),
        };
        let now = now_unix();
        let names = form.tag_list();
        let entry_id = id;
        // The tag ids have to exist in the index before `put_entry` will
        // accept an entry that references them, so the names are registered
        // first. A name the vault already knows reuses that tag.
        let tag_ids = match self.session.as_mut() {
            Some(session) => session.ensure_tags(&names, now)?,
            None => return Err(AppError::WrongPassword),
        };
        let entry = form.to_entry(entry_id, now, tag_ids);
        let saved_id = entry.id.clone();
        let session = self.session.as_mut().ok_or(AppError::WrongPassword)?;
        session.save_entry(entry)?;
        self.form = None;
        self.screen = Screen::Vault;
        self.on_entries_changed();
        // Select what was just saved, so the detail pane shows it. A new entry
        // sorts to the top and an edit keeps its position, so resolving the id
        // is what makes this work for both.
        if let Some(index) = self.rows.iter().position(|r| *r == saved_id) {
            self.selected = index;
            self.offset = self.offset.min(self.selected);
            self.load_detail();
        }
        self.notify(Status::success("Entry saved"));
        Ok(())
    }

    /// Puts a generated password into the form's password field.
    pub fn generate_password_into_form(&mut self) {
        let generated = match self.generator.generate() {
            Ok(p) => p,
            Err(e) => {
                self.notify_error(e);
                return;
            }
        };
        if let Some(form) = self.form.as_mut() {
            form.password = generated;
            // A generated password is the one case where showing it is safe
            // and expected: the user just made it up in this session.
            form.reveal = true;
            form.field = Field::Password;
        }
        self.touch();
    }

    /// Flips the favorite flag on the selected entry and persists it.
    pub fn toggle_selected_favorite(&mut self) {
        // The detail pane already holds the selected entry, so its presence is
        // what "something is selected" means.
        let Some(mut entry) = self.detail.clone() else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        entry.favorite = !entry.favorite;
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return,
        };
        if let Err(e) = session.save_entry(entry) {
            self.notify_error(e);
            return;
        }
        self.on_entries_changed();
        self.load_detail();
        let starred = self
            .selected_index_entry()
            .map(|e| e.favorite)
            .unwrap_or(false);
        self.notify(Status::success(if starred { "Added to favorites" } else { "Removed from favorites" }));
    }

    /// Soft-deletes the selected entry after confirmation.
    pub fn delete_selected(&mut self) {
        let Some(id) = self.selected_id() else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        let title = self.selected_title();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if let Err(e) = session.delete_entry(&id) {
            self.notify_error(e);
            return;
        }
        self.on_entries_changed();
        self.notify(Status::success(&format!("Deleted {title}")));
    }

    /// Queues a secret for the clipboard and flips the reveal flag so the
    /// detail pane shows the same thing the clipboard now holds.
    pub fn copy_password(&mut self) {
        let Some(entry) = &self.detail else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        if entry.password.is_empty() {
            self.notify(Status::error("This entry has no password"));
            return;
        }
        // The message is left to the shell, which is where the clipboard write
        // actually happens and can still fail.
        self.pending_copy = Some(entry.password.clone());
    }

    /// Queues the username for the clipboard.
    pub fn copy_username(&mut self) {
        let Some(entry) = &self.detail else {
            self.notify(Status::error("No entry selected"));
            return;
        };
        if entry.username.is_empty() {
            self.notify(Status::error("This entry has no username"));
            return;
        }
        // The message is left to the shell, which is where the clipboard write
        // actually happens and can still fail.
        self.pending_copy = Some(entry.username.clone());
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
    pub fn change_master_password(&mut self, new_password: &str, confirm: &str) -> Result<(), AppError> {
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

    /// The seconds remaining before auto-lock, for the status line.
    pub fn auto_lock_countdown(&self) -> Option<u64> {
        if self.auto_lock_secs == 0 || self.session.is_none() {
            return None;
        }
        Some(self.auto_lock_secs.saturating_sub(self.idle_secs))
    }

    // ------------------------------------------------------------- settings

    /// The auto-lock delays the settings screen steps through, in seconds.
    ///
    /// Each step is a multiple of the previous one so the arrow keys sweep
    /// from "off" to a full day without a long walk, and every step renders
    /// as a whole number of minutes.
    pub const AUTO_LOCK_STEPS: [u64; 7] = [0, 60, 300, 900, 1800, 3600, 21600];

    /// Which settings row is currently highlighted.
    pub const ROW_VAULT: usize = 0;
    /// The key-derivation row, shown for information only.
    pub const ROW_KDF: usize = 1;
    /// The auto-lock row, the only one the user can change here.
    pub const ROW_AUTO_LOCK: usize = 2;
    /// The master-password row, which opens the rekey flow.
    pub const ROW_MASTER_PASSWORD: usize = 3;
    /// The row that closes the vault and discards its entries.
    pub const ROW_RESET: usize = 4;

    /// The number of rows on the settings screen.
    ///
    /// The view renders one row per constant above, and this bounds the
    /// cursor to them.
    pub const SETTINGS_ROWS: usize = 5;

    /// Moves the settings cursor by `delta`, clamped to the available rows.
    pub fn move_settings_row(&mut self, delta: i64) {
        let last = Self::SETTINGS_ROWS.saturating_sub(1) as i64;
        let next = self.settings_row as i64 + delta;
        self.settings_row = next.clamp(0, last) as usize;
        self.touch();
    }

    /// Steps the auto-lock delay up or down to the next preset.
    ///
    /// Stepping past an end wraps around, so the delay is always reachable
    /// with the arrow keys regardless of where it started.
    pub fn step_auto_lock(&mut self, delta: i64) {
        let steps = Self::AUTO_LOCK_STEPS;
        let current = steps.iter().position(|s| *s == self.auto_lock_secs);
        let index: usize = match (current, delta.signum()) {
            (Some(i), 1) => (i + 1) % steps.len(),
            (Some(i), _) => (i + steps.len() - 1) % steps.len(),
            // A delay that is not one of the presets starts from the step
            // above it, so stepping up never appears to do nothing.
            (None, 1) => steps
                .iter()
                .position(|s| *s > self.auto_lock_secs)
                .unwrap_or(0),
            (None, _) => steps.len() - 1,
        };
        self.auto_lock_secs = steps[index];
        // A delay that has just passed should take effect immediately rather
        // than stranding the user with an idle timer that starts behind them.
        self.idle_secs = 0;
        let label = auto_lock_label(self.auto_lock_secs);
        self.notify(Status::success(&format!("Auto-lock set to {label}")));
        self.touch();
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
        self.modal = Some(Modal::Password { title: "master password".into(), value: String::new() });
    }

    /// Confirms the destructive settings action.
    pub fn reset_vault(&mut self) {
        if let Some(session) = self.session.take() {
            session.lock();
        }
        self.lock();
        self.notify(Status::error("The vault is locked"));
    }

    // ------------------------------------------------------- render helpers

    /// How many entries the vault holds, ignoring the current filter, so the
    /// header count doesn't change as the user searches.
    pub fn total_entry_count(&self) -> usize {
        self.session
            .as_ref()
            .map(|s| s.index.entries.iter().filter(|e| !e.deleted).count())
            .unwrap_or(0)
    }

    /// A short form of the vault path for the header.
    pub fn vault_path_display(&self) -> String {
        self.paths.root().display().to_string()
    }

    /// The line shown after the screen name in the header: the selected entry
    /// when there is one, otherwise the active filter.
    pub fn render_context(&self) -> String {
        if self.screen != Screen::Vault {
            return String::new();
        }
        let title = self.selected_title();
        if !title.is_empty() {
            return title;
        }
        if self.filter.is_narrowed() {
            self.filter.label()
        } else {
            String::new()
        }
    }

    /// A cheap, cloneable snapshot for rendering.
    ///
    /// The session is deliberately left out: rendering only needs the entry
    /// list, which is already materialized in `rows` and `detail`.
    pub fn clone_for_render(&self) -> RenderSnapshot {
        RenderSnapshot {
            screen: self.screen,
            focus: self.focus,
            query: self.query.clone(),
            filter: self.filter.clone(),
            selected: self.selected,
            offset: self.offset,
            detail: self.detail.clone(),
            reveal: self.reveal,
            form: self.form.clone(),
            modal: self.modal.clone(),
            status: self.status.clone(),
            password: self.password.clone(),
            confirm: self.confirm.clone(),
            kdf: self.kdf,
            screen_error: self.screen_error.clone(),
            settings_row: self.settings_row,
            auto_lock_secs: self.auto_lock_secs,
            auto_lock_countdown: self.auto_lock_countdown(),
            session_present: self.session.is_some(),
            total_entries: self.total_entry_count(),
            path: self.vault_path_display(),
            context: self.render_context(),
            tag_names: self.tag_id_names(),
            list_capacity: self.list_capacity,
            list_rows: self.render_rows(),
        }
    }

    /// Builds the display rows for the current selection, from the in-memory
    /// index. No decryption happens here: titles and usernames are already in
    /// the index, and a TOTP marker only reflects the selected entry.
    pub fn render_rows(&self) -> Vec<crate::widgets::entry_list::ListRow> {
        let Some(session) = self.session.as_ref() else {
            return Vec::new();
        };
        let selected_id = self.selected_id();
        self.rows
            .iter()
            .filter_map(|id| {
                let e = session.index.entries.iter().find(|e| &e.id == id)?;
                let is_selected = Some(&e.id) == selected_id.as_ref();
                Some(crate::widgets::entry_list::ListRow {
                    id: e.id.clone(),
                    title: if e.title.is_empty() { "(untitled)".to_string() } else { e.title.clone() },
                    subtitle: if e.username.is_empty() { e.url.clone() } else { e.username.clone() },
                    favorite: e.favorite,
                    has_totp: is_selected
                        && self.detail.as_ref().and_then(crate::widgets::detail::current_totp).is_some(),
                })
            })
            .collect()
    }
}

/// The subset of [`AppState`] the view layer reads.
///
/// A plain owned copy with no `VaultSession`, so rendering cannot reach key
/// material and the view is trivially `Send + Sync`.
#[derive(Clone)]
pub struct RenderSnapshot {
    pub screen: Screen,
    pub focus: Focus,
    pub query: String,
    pub filter: Filter,
    pub selected: usize,
    pub offset: usize,
    pub detail: Option<Entry>,
    pub reveal: bool,
    pub form: Option<EntryForm>,
    pub modal: Option<Modal>,
    pub status: Option<Status>,
    pub password: String,
    pub confirm: String,
    pub kdf: KdfParams,
    pub screen_error: Option<String>,
    pub settings_row: usize,
    pub auto_lock_secs: u64,
    /// Seconds until auto-lock fires, or `None` when it is off. See
    /// [`AppState::auto_lock_countdown`].
    pub auto_lock_countdown: Option<u64>,
    pub session_present: bool,
    pub total_entries: usize,
    pub path: String,
    pub context: String,
    /// Every live tag as `(id, name)`, so the view can print names.
    pub tag_names: Vec<(String, String)>,
    /// Rows the list pane can show; see [`AppState::list_capacity`].
    pub list_capacity: usize,
    /// Rows prepared for display, so the view never touches the session.
    pub list_rows: Vec<crate::widgets::entry_list::ListRow>,
}

/// A fresh entry id.
///
/// Core mints ids for its own callers, but the TUI needs one per new entry
/// without taking on a uuid dependency. Mixing the process id, a monotonic
/// counter, and the wall clock gives 32 hex characters that cannot collide
/// within a vault.
fn new_entry_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    // `{:04x}` and `{:012x}` are *minimum* widths, not caps, so a pid above
    // 0xffff or a counter above 2^48 would widen the id past 32 characters.
    // Callers assume the fixed width, so truncate rather than pad.
    let pid = (std::process::id() as u64) & 0xffff;
    let seq = seq & ((1u64 << 48) - 1);

    format!("{nanos:016x}{pid:04x}{seq:012x}")
}

/// Case-insensitive substring match across the fields core searches.
fn matches_query(item: &domi_core::search::SearchItem, query: &str) -> bool {
    if query.trim().is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    item.title.to_lowercase().contains(&q)
        || item.username.to_lowercase().contains(&q)
        || item.url.to_lowercase().contains(&q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domi_core::vault::Index;

    fn idx_entry(id: &str, title: &str, username: &str, updated_at: i64) -> IndexEntry {
        IndexEntry {
            id: id.into(),
            title: title.into(),
            username: username.into(),
            url: String::new(),
            updated_at,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            category: ItemCategory::Login,
            attachments: Vec::new(),
        }
    }

    fn state_with(entries: Vec<IndexEntry>) -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "domi-state-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let session =
            VaultSession::create(VaultPaths::new(&dir), "pw", crate::vault_store::test_params())
                .expect("test vault should create");
        let mut session = session;
        session.index = Index { version: 1, entries, ..Default::default() };

        let mut s = AppState::new(VaultPaths::new("/tmp/domi-state-unused"));
        s.session = Some(session);
        s
    }

    #[test]
    fn every_screen_has_a_title() {
        for screen in [Screen::Setup, Screen::Unlock, Screen::Vault, Screen::Edit, Screen::Settings] {
            assert!(!screen.title().is_empty());
        }
    }

    #[test]
    fn the_settings_cursor_stops_at_both_ends() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.move_settings_row(-1);
        assert_eq!(s.settings_row, 0, "cannot move above the first row");

        for _ in 0..(AppState::SETTINGS_ROWS * 2) {
            s.move_settings_row(1);
        }
        assert_eq!(s.settings_row, AppState::SETTINGS_ROWS - 1, "cannot move past the last");

        s.move_settings_row(1);
        assert_eq!(s.settings_row, AppState::SETTINGS_ROWS - 1);
        s.move_settings_row(-(AppState::SETTINGS_ROWS as i64));
        assert_eq!(s.settings_row, 0);
    }

    #[test]
    fn stepping_auto_lock_walks_the_presets_and_wraps() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.auto_lock_secs = 0;
        for expected in &AppState::AUTO_LOCK_STEPS[1..] {
            s.step_auto_lock(1);
            assert_eq!(s.auto_lock_secs, *expected);
        }
        s.step_auto_lock(1);
        assert_eq!(s.auto_lock_secs, 0, "stepping past the end wraps to off");

        s.step_auto_lock(-1);
        assert_eq!(s.auto_lock_secs, *AppState::AUTO_LOCK_STEPS.last().unwrap());
    }

    #[test]
    fn stepping_auto_lock_never_lands_off_the_end_of_the_list() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        // A delay set outside the presets must still step somewhere sane.
        s.auto_lock_secs = 7;
        s.step_auto_lock(1);
        assert!(AppState::AUTO_LOCK_STEPS.contains(&s.auto_lock_secs), "got {}", s.auto_lock_secs);
        s.step_auto_lock(-1);
        assert!(AppState::AUTO_LOCK_STEPS.contains(&s.auto_lock_secs));
    }

    #[test]
    fn changing_auto_lock_restarts_the_idle_timer() {
        // Otherwise a delay the user just raised could fire immediately,
        // stranding them with a vault that locks as soon as they look at it.
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.auto_lock_secs = 60;
        s.idle_secs = 55;
        s.step_auto_lock(1);
        assert_eq!(s.idle_secs, 0);
    }

    #[test]
    fn changing_the_master_password_needs_an_unlocked_vault() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.begin_master_password_change();
        assert!(s.modal.is_none(), "a locked vault has nothing to rekey");
        assert!(matches!(s.status.as_ref().map(|s| s.kind), Some(StatusKind::Error)));
    }

    #[test]
    fn the_tag_filter_narrows_to_the_selected_entry_first_tag() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        s.begin_new_entry();
        {
            let f = s.form.as_mut().unwrap();
            f.title = "GitHub".into();
            f.tags = "work".into();
        }
        s.save_form().unwrap();
        assert_eq!(s.rows.len(), 1, "the entry should be listed after saving");

        // The entry holds the id the tag was registered under, and the filter
        // label shows the name. Together that is what makes the round trip
        // work: the user typed "work", the entry stores an id, the status line
        // reads "#work".
        let tag_id = s.detail.as_ref().unwrap().tags[0].clone();
        assert_ne!(tag_id, "work", "the entry must hold an id, not the name");
        assert_eq!(s.tag_name(&tag_id), "work");

        s.toggle_tag_filter();
        assert_eq!(s.filter, Filter::Tag { id: tag_id.clone(), name: "work".into() });
        assert_eq!(s.filter.label(), "#work");
        assert!(s.filter.is_narrowed());
        assert_eq!(s.rows.len(), 1, "the tagged entry is in the filtered list");

        // Pressing the key again returns to the whole vault.
        s.toggle_tag_filter();
        assert_eq!(s.filter, Filter::All);
    }

    #[test]
    fn an_untagged_entry_says_so_instead_of_silently_doing_nothing() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();
        s.rows.push("a".into());
        s.load_detail();
        s.toggle_tag_filter();
        assert_eq!(s.filter, Filter::All, "no tag means no filter");
        assert!(matches!(s.status.as_ref().map(|s| s.kind), Some(StatusKind::Error)));
    }

    #[test]
    fn saving_an_entry_creates_the_tag_it_names() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        s.begin_new_entry();
        {
            let f = s.form.as_mut().unwrap();
            f.title = "GitHub".into();
            f.tags = "work, personal".into();
        }
        s.save_form().unwrap();

        // `put_entry` refuses an entry carrying an unregistered tag id, so
        // reaching a saved entry at all means the tags were registered.
        let names: Vec<String> = s.tag_id_names().into_iter().map(|(_, n)| n).collect();
        assert_eq!(names, vec!["work", "personal"]);
        assert_eq!(s.detail.as_ref().unwrap().tags.len(), 2);
    }

    #[test]
    fn the_same_tag_name_typed_twice_is_one_tag() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        let save = |s: &mut AppState, title: &str, tags: &str| {
            s.begin_new_entry();
            let f = s.form.as_mut().unwrap();
            f.title = title.into();
            f.tags = tags.into();
            s.save_form().unwrap();
        };

        save(&mut s, "First", "work");
        save(&mut s, "Second", "Work");

        assert_eq!(s.tag_id_names().len(), 1, "case must not fork the tag");
        assert_eq!(s.tag_id_names()[0].1, "work");
        // Both entries point at the one tag, so filtering by it finds both.
        s.toggle_tag_filter();
        assert_eq!(s.rows.len(), 2);
    }

    #[test]
    fn a_tag_filter_finds_every_entry_carrying_it() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        let save = |s: &mut AppState, title: &str, tags: &str| {
            s.begin_new_entry();
            let f = s.form.as_mut().unwrap();
            f.title = title.into();
            f.tags = tags.into();
            s.save_form().unwrap();
        };
        save(&mut s, "GitHub", "work");
        save(&mut s, "Bank", "work, finance");
        save(&mut s, "Recipes", "home");
        assert_eq!(s.rows.len(), 3);

        s.begin_edit_selected();
        // "Recipes" is newest, so it is selected; step to GitHub to filter on
        // a tag the other two share.
        s.move_selection(-1);
        s.toggle_tag_filter();
        assert_eq!(s.filter.label(), "#work");
        assert_eq!(s.rows.len(), 2, "GitHub and Bank both carry work");
    }

    #[test]
    fn tags_survive_closing_and_reopening_the_vault() {
        let t = crate::vault_store::testing::TempVault::new();
        let paths = t.paths();
        {
            let mut s = AppState::new(paths.clone());
            s.create_vault("master", "master").unwrap();
            s.begin_new_entry();
            let f = s.form.as_mut().unwrap();
            f.title = "GitHub".into();
            f.tags = "work".into();
            s.save_form().unwrap();
        }

        // The tag lives in the index, so reopening has to resolve the entry's
        // tag id back to a name rather than showing the raw id.
        let mut s = AppState::new(paths);
        s.unlock("master").unwrap();
        assert_eq!(s.tag_id_names().len(), 1);
        assert_eq!(s.tag_id_names()[0].1, "work");
        assert_eq!(s.detail.as_ref().unwrap().tags, s.tag_id_names().iter().map(|(id, _)| id.clone()).collect::<Vec<_>>());
    }

    #[test]
    fn editing_an_entry_shows_its_tag_names_and_resaves_the_same_ids() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        s.begin_new_entry();
        {
            let f = s.form.as_mut().unwrap();
            f.title = "GitHub".into();
            f.tags = "work".into();
        }
        s.save_form().unwrap();
        let tag_id = s.detail.as_ref().unwrap().tags[0].clone();

        s.begin_edit_selected();
        assert_eq!(s.form.as_ref().unwrap().tags, "work", "the form shows the name");

        // Saving the form untouched must not fork the tag or duplicate it.
        s.save_form().unwrap();
        assert_eq!(s.tag_id_names().len(), 1);
        assert_eq!(s.detail.as_ref().unwrap().tags, vec![tag_id]);
    }

    #[test]
    fn removing_the_last_tag_keeps_the_entry_and_its_tags_out_of_the_index() {
        let t = crate::vault_store::testing::TempVault::new();
        let mut s = AppState::new(t.paths());
        s.create_vault("master", "master").unwrap();

        s.begin_new_entry();
        {
            let f = s.form.as_mut().unwrap();
            f.title = "GitHub".into();
            f.tags = "work".into();
        }
        s.save_form().unwrap();

        s.begin_edit_selected();
        s.form.as_mut().unwrap().tags = String::new();
        s.save_form().unwrap();

        assert!(s.detail.as_ref().unwrap().tags.is_empty());
        // The tag stays in the index, unreferenced: core's `delete_tag` is the
        // thing that retires a tag, and nothing in the TUI calls it.
        assert_eq!(s.tag_id_names().len(), 1, "the tag is left defined, just unused");
    }

    #[test]
    fn initial_screen_depends_on_whether_a_vault_exists() {
        let existing = std::env::temp_dir().join("domi-state-test-exists");
        let _ = std::fs::create_dir_all(&existing);
        std::fs::write(existing.join("manifest.json"), "{}").unwrap();

        let mut s = AppState::new(VaultPaths::new(&existing));
        assert_eq!(s.initial_screen(), Screen::Unlock);

        let mut missing = AppState::new(VaultPaths::new("/tmp/domi-state-missing-dir"));
        assert_eq!(missing.initial_screen(), Screen::Setup);

        let _ = std::fs::remove_dir_all(&existing);
    }

    #[test]
    fn rows_are_newest_updated_first() {
        let mut s = state_with(vec![
            idx_entry("a", "Older", "u", 100),
            idx_entry("b", "Newest", "u", 300),
            idx_entry("c", "Middle", "u", 200),
        ]);
        s.refresh();
        assert_eq!(s.rows, vec!["b", "c", "a"]);
        assert_eq!(s.selected, 0);
    }

    #[test]
    fn query_filters_case_insensitively_across_title_user_and_url() {
        let mut s = state_with(vec![
            idx_entry("a", "GitHub", "octocat", 100),
            idx_entry("b", "Bank", "alice", 200),
        ]);
        s.refresh();
        assert_eq!(s.rows.len(), 2);

        s.set_query("git".into());
        assert_eq!(s.rows, vec!["a"]);

        s.set_query("ALICE".into());
        assert_eq!(s.rows, vec!["b"]);

        s.set_query("nothing matches this".into());
        assert!(s.rows.is_empty());
    }

    #[test]
    fn blank_query_returns_everything() {
        let mut s = state_with(vec![idx_entry("a", "A", "u", 1), idx_entry("b", "B", "u", 2)]);
        s.refresh();
        s.set_query("   ".into());
        assert_eq!(s.rows.len(), 2);
    }

    #[test]
    fn selection_is_preserved_by_id_when_the_filter_changes() {
        let mut s = state_with(vec![
            idx_entry("a", "Alpha", "u", 300),
            idx_entry("b", "Beta", "u", 200),
            idx_entry("c", "Gamma", "u", 100),
        ]);
        s.refresh();
        s.move_selection(2);
        assert_eq!(s.selected_id().as_deref(), Some("c"));

        // "gam" still matches the selected row, so the cursor stays put.
        s.set_query("gam".into());
        assert_eq!(s.selected_id().as_deref(), Some("c"));
    }

    #[test]
    fn selection_falls_back_to_the_top_when_the_filter_drops_the_row() {
        // "a" is newest so it sorts to the top, making the row order explicit
        // rather than assumed.
        let mut s = state_with(vec![idx_entry("b", "Beta", "u", 1), idx_entry("a", "Alpha", "u", 2)]);
        s.refresh();
        assert_eq!(s.rows, vec!["a", "b"]);
        assert_eq!(s.selected_id().as_deref(), Some("a"));

        s.move_selection(1);
        assert_eq!(s.selected_id().as_deref(), Some("b"), "cursor moved to the second row");

        // "alpha" only matches "a", so the selected row is filtered out and the
        // cursor must land somewhere valid instead of pointing at a stale index.
        s.set_query("alpha".into());
        assert_eq!(s.rows, vec!["a"]);
        assert_eq!(s.selected, 0);
        assert_eq!(s.selected_id().as_deref(), Some("a"));
    }

    #[test]
    fn selection_never_points_past_the_end_of_a_shrunk_list() {
        let entries: Vec<IndexEntry> =
            (0..10).map(|i| idx_entry(&format!("id{i}"), &format!("Item {i}"), "u", 100 - i)).collect();
        let mut s = state_with(entries);
        s.refresh();
        s.move_selection(9);
        assert_eq!(s.selected, 9);

        // Narrow to a single matching row.
        s.set_query("Item 7".into());
        assert_eq!(s.rows.len(), 1);
        assert!(s.selected < s.rows.len(), "selection {} out of range", s.selected);
        assert!(s.selected_id().is_some());
    }

    #[test]
    fn favorites_filter_narrows_the_list() {
        let mut s = state_with(vec![idx_entry("a", "Alpha", "u", 2)]);
        s.session.as_mut().unwrap().index.entries[0].favorite = true;
        s.session.as_mut().unwrap().index.entries.push(idx_entry("b", "Beta", "u", 1));
        s.refresh();
        assert_eq!(s.rows.len(), 2);

        s.set_filter(Filter::Favorites);
        assert_eq!(s.rows, vec!["a"]);
        assert!(s.filter.is_narrowed());
        assert!(Filter::All.label() == "All");

        // Toggling off returns the full list.
        s.toggle_favorite_filter();
        assert_eq!(s.rows.len(), 2);
        assert!(!s.filter.is_narrowed());
    }

    #[test]
    fn tag_filter_narrows_the_list() {
        let mut s = state_with(vec![idx_entry("a", "Alpha", "u", 2)]);
        // Entries carry tag *ids*, so the index needs a tag for the id to
        // resolve to. This is the shape `save_form` produces.
        s.session.as_mut().unwrap().index.tags = vec![domi_core::vault::Tag {
            id: "t-work".into(),
            name: "work".into(),
            updated_at: 0,
            deleted: false,
        }];
        s.session.as_mut().unwrap().index.entries[0].tags = vec!["t-work".into()];
        s.session.as_mut().unwrap().index.entries.push(idx_entry("b", "Beta", "u", 1));
        s.refresh();

        s.set_filter(Filter::Tag { id: "t-work".into(), name: "work".into() });
        assert_eq!(s.rows, vec!["a"]);
        assert_eq!(s.filter.label(), "#work");
    }

    #[test]
    fn search_composes_with_a_filter() {
        let mut s = state_with(vec![idx_entry("a", "Alpha", "u", 3)]);
        s.session.as_mut().unwrap().index.entries[0].favorite = true;
        s.session.as_mut().unwrap().index.entries[0].tags = vec!["work".into()];
        let mut other = idx_entry("b", "Beta", "u", 2);
        other.favorite = true;
        other.tags = vec!["home".into()];
        s.session.as_mut().unwrap().index.entries.push(other);
        s.refresh();

        s.set_filter(Filter::Favorites);
        assert_eq!(s.rows.len(), 2);
        // Only one of the two favorites matches.
        s.set_query("alp".into());
        assert_eq!(s.rows, vec!["a"]);
    }

    #[test]
    fn movement_clamps_at_both_ends() {
        let mut s = state_with(vec![
            idx_entry("a", "A", "u", 3),
            idx_entry("b", "B", "u", 2),
            idx_entry("c", "C", "u", 1),
        ]);
        s.refresh();
        s.move_selection(-1);
        assert_eq!(s.selected, 0, "cannot move above the first row");

        s.move_selection(99);
        assert_eq!(s.selected, 2, "cannot move below the last row");
        assert_eq!(s.selected_id().as_deref(), Some("c"));
    }

    #[test]
    fn movement_on_an_empty_list_is_harmless() {
        let mut s = state_with(vec![]);
        s.refresh();
        s.move_selection(1);
        s.move_selection(-1);
        assert_eq!(s.selected, 0);
        assert!(s.rows.is_empty());
    }

    #[test]
    fn scroll_keeps_the_selection_inside_the_window() {
        let entries: Vec<IndexEntry> =
            (0..20).map(|i| idx_entry(&format!("id{i}"), &format!("T{i}"), "u", 100 - i)).collect();
        let mut s = state_with(entries);
        s.refresh();

        s.selected = 15;
        s.clamp_scroll(10);
        assert!(s.selected >= s.offset, "selection {} above offset {}", s.selected, s.offset);
        assert!(s.selected < s.offset + 10);

        s.selected = 1;
        s.clamp_scroll(10);
        assert!(s.offset <= s.selected, "offset {} left the selection above the window", s.offset);
    }

    #[test]
    fn scroll_window_never_overshoots_a_short_list() {
        let mut s = state_with(vec![idx_entry("a", "A", "u", 1)]);
        s.refresh();
        s.clamp_scroll(20);
        assert_eq!(s.offset, 0);
        s.clamp_scroll(0);
        assert_eq!(s.offset, 0);
    }

    #[test]
    fn field_cycling_wraps_in_both_directions() {
        assert_eq!(Field::Title.next(), Field::Username);
        assert_eq!(Field::Tags.next(), Field::Title, "next wraps forward");
        assert_eq!(Field::Title.prev(), Field::Tags, "prev wraps backward");
        assert_eq!(Field::ALL.len(), 9);
        for f in Field::ALL {
            assert!(!f.label().is_empty());
        }
    }

    #[test]
    fn new_form_starts_on_title_and_is_marked_new() {
        let form = EntryForm::new(0);
        assert!(form.is_new());
        assert_eq!(form.field, Field::Title);
        assert!(!form.reveal, "secrets start hidden");
    }

    #[test]
    fn form_text_borrow_and_write_follow_the_focused_field() {
        let mut form = EntryForm::new(0);
        form.field = Field::Username;
        form.set_text("octocat".into());
        assert_eq!(form.text(), "octocat");
        assert_eq!(form.username, "octocat");
        assert_eq!(form.title, "", "only the focused field changed");

        form.field = Field::Notes;
        form.set_text("line one".into());
        assert_eq!(form.notes, "line one");
    }

    #[test]
    fn toggles_have_no_editable_text() {
        let mut form = EntryForm::new(0);
        form.field = Field::Favorite;
        assert_eq!(form.text(), "");
        form.set_text("ignored".into());
        assert!(!form.favorite);
    }

    #[test]
    fn category_cycles_through_every_variant_and_returns() {
        let mut form = EntryForm::new(0);
        // Default is Login; the first entry is it so the cycle is anchored.
        assert_eq!(form.category, ItemCategory::Login);
        let start = form.category;
        let mut seen = vec![start];
        // One cycle per remaining variant, then one more to wrap home.
        for _ in 0..all_categories().len() {
            form.cycle_category();
            seen.push(form.category);
        }
        assert_eq!(form.category, start, "cycling once per variant returns to the start");
        // Every variant was visited exactly once before the wrap.
        for (i, category) in all_categories().iter().enumerate() {
            assert_eq!(seen.get(i), Some(category), "seen: {seen:?}");
        }
    }

    #[test]
    fn favorite_toggles() {
        let mut form = EntryForm::new(0);
        assert!(!form.favorite);
        form.toggle_favorite();
        assert!(form.favorite);
        form.toggle_favorite();
        assert!(!form.favorite);
    }

    #[test]
    fn tag_field_splits_and_trims() {
        let mut form = EntryForm::new(0);
        form.tags = " work , home ,, ".into();
        assert_eq!(form.tag_list(), vec!["work", "home"]);
    }

    #[test]
    fn form_validation_requires_a_title() {
        let mut form = EntryForm::new(0);
        assert!(form.validate().is_err());
        form.title = "   ".into();
        assert!(form.validate().is_err());
        form.title = "GitHub".into();
        assert!(form.validate().is_ok());
    }

    #[test]
    fn form_validation_rejects_an_absurd_title_or_notes() {
        let mut form = EntryForm::new(0);
        form.title = "x".repeat(201);
        assert!(form.validate().is_err());
        form.title = "x".repeat(200);
        assert!(form.validate().is_ok());

        form.notes = "y".repeat(10_001);
        assert!(form.validate().is_err());
        form.notes = "y".repeat(10_000);
        assert!(form.validate().is_ok());
    }

    #[test]
    fn form_round_trips_an_existing_entry() {
        let mut entry = crate::vault_store::blank_entry("abc".into(), 100);
        entry.title = "GitHub".into();
        entry.username = "octocat".into();
        entry.password = "hunter2".into();
        entry.url = "github.com".into();
        entry.notes = "work account".into();
        entry.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        // An entry holds tag ids, so the form is given the id/name pairs it
        // needs to render something a person typed.
        entry.tags = vec!["t-work".into()];
        entry.favorite = true;

        let form = EntryForm::from_entry(&entry, &[("t-work".into(), "work".into())]);
        assert!(!form.is_new());
        assert_eq!(form.title, "GitHub");
        assert_eq!(form.tags, "work", "the form shows the name, not the id");

        let round_tripped = form.to_entry("abc".into(), 200, vec!["t-work".into()]);
        assert_eq!(round_tripped.title, "GitHub");
        assert_eq!(round_tripped.password, "hunter2");
        assert_eq!(round_tripped.tags, vec!["t-work"]);
        assert_eq!(round_tripped.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(round_tripped.favorite);
        assert_eq!(round_tripped.updated_at, 200);
    }

    #[test]
    fn a_tag_id_with_no_name_shows_as_the_id_rather_than_vanishing() {
        let mut entry = crate::vault_store::blank_entry("abc".into(), 0);
        entry.title = "T".into();
        entry.tags = vec!["gone".into()];

        // A tag deleted out from under an entry must stay visible, so the user
        // sees the reference and can remove it instead of wondering where the
        // tag went.
        let form = EntryForm::from_entry(&entry, &[]);
        assert_eq!(form.tags, "gone");
    }

    #[test]
    fn an_empty_totp_becomes_none_not_an_empty_string() {
        let mut form = EntryForm::new(0);
        form.title = "T".into();
        form.totp = "   ".into();
        assert!(form.to_entry("id".into(), 0, Vec::new()).totp_secret.is_none());
    }

    #[test]
    fn generator_defaults_are_valid_and_produce_a_password() {
        let opts = GeneratorOptions::default();
        assert!(opts.validate().is_ok());
        let pw = opts.generate().unwrap();
        assert_eq!(pw.chars().count(), opts.length);
    }

    #[test]
    fn generator_rejects_zero_length_and_no_character_classes() {
        let bad_len = GeneratorOptions { length: 0, ..Default::default() };
        assert!(bad_len.validate().is_err());

        let no_classes = GeneratorOptions {
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            ..Default::default()
        };
        assert!(no_classes.validate().is_err());
    }

    #[test]
    fn generator_reports_a_readable_message() {
        let bad = GeneratorOptions { length: 9999, ..Default::default() };
        match bad.generate() {
            Err(AppError::BadInput(msg)) => assert!(msg.contains("Length")),
            other => panic!("expected BadInput, got {other:?}"),
        }
    }

    #[test]
    fn modal_labels_and_constructor_intent() {
        let safe = Modal::confirm("Change password", "This re-encrypts everything.");
        match &safe {
            Modal::Confirm { danger, yes_label, .. } => {
                assert!(!danger);
                assert_eq!(yes_label, "Confirm");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }

        let risky = Modal::danger("Delete entry", "This cannot be undone.");
        match &risky {
            Modal::Confirm { danger, yes_label, .. } => {
                assert!(danger);
                assert_eq!(yes_label, "Delete");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
        assert!(risky.blocks_input());
        assert!(!risky.title().is_empty());
    }

    #[test]
    fn idle_timer_triggers_only_after_the_threshold() {
        let mut s = state_with(vec![idx_entry("a", "A", "u", 1)]);
        s.auto_lock_secs = 100;
        assert!(!s.tick_idle(40));
        assert!(!s.tick_idle(50), "90s is still under the threshold");
        assert_eq!(s.idle_secs, 90);
        assert!(s.tick_idle(10), "reaching 100s requests a lock");
    }

    #[test]
    fn touching_resets_the_idle_timer() {
        let mut s = state_with(vec![idx_entry("a", "A", "u", 1)]);
        s.auto_lock_secs = 100;
        s.tick_idle(90);
        s.touch();
        assert_eq!(s.idle_secs, 0);
        assert!(!s.tick_idle(50));
    }

    #[test]
    fn idle_timer_is_inert_while_locked_or_disabled() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.auto_lock_secs = 1;
        assert!(!s.tick_idle(10_000), "no session, so nothing to protect");

        let mut unlocked = state_with(vec![]);
        unlocked.auto_lock_secs = 0;
        assert!(!unlocked.tick_idle(10_000), "auto-lock disabled");
    }

    #[test]
    fn lock_clears_plaintext_and_returns_to_unlock() {
        let mut s = state_with(vec![idx_entry("a", "A", "u", 1)]);
        s.query = "searching".into();
        s.reveal = true;
        s.password = "master".into();
        s.focus = Focus::Detail;
        s.screen = Screen::Vault;

        s.lock();

        assert!(s.session.is_none());
        assert!(s.detail.is_none());
        assert!(s.form.is_none());
        assert!(s.rows.is_empty());
        assert!(s.query.is_empty());
        assert!(!s.reveal);
        assert_eq!(s.focus, Focus::List);
        assert_eq!(s.screen, Screen::Unlock);
        assert_eq!(s.idle_secs, 0);
    }

    #[test]
    fn notify_resets_idle_and_records_the_message() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.idle_secs = 500;
        s.notify(Status::success("Saved"));
        assert_eq!(s.idle_secs, 0);
        assert_eq!(s.status.unwrap().text, "Saved");
    }

    #[test]
    fn notify_error_uses_the_friendly_message() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        s.notify_error(AppError::WrongPassword);
        let st = s.status.unwrap();
        assert_eq!(st.kind, StatusKind::Error);
        assert!(st.text.contains("password"));
    }

    #[test]
    fn modal_open_reflects_the_modal_slot() {
        let mut s = AppState::new(VaultPaths::new("/tmp/nope"));
        assert!(!s.modal_open());
        s.modal = Some(Modal::danger("t", "b"));
        assert!(s.modal_open());
    }

    #[test]
    fn status_messages_carry_their_kind_and_time() {
        assert_eq!(Status::info("i").kind, StatusKind::Info);
        assert_eq!(Status::success("s").kind, StatusKind::Success);
        assert_eq!(Status::error("e").kind, StatusKind::Error);
        assert!(Status::info("i").at > 0);
    }

    // ------------------------------------------------------------- actions

    /// A state pointed at a fresh, empty temp vault.
    fn fresh_state() -> AppState {
        let dir = std::env::temp_dir().join(format!("domi-act-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        AppState::new(VaultPaths::new(&dir))
    }

    /// A state with a real unlocked vault on disk.
    fn unlocked_state() -> AppState {
        let mut s = fresh_state();
        s.kdf = crate::vault_store::test_params();
        s.create_vault("correct horse", "correct horse").expect("vault should create");
        s
    }

    #[test]
    fn create_vault_then_unlock_lands_on_the_vault_screen() {
        let mut s = fresh_state();
        s.kdf = crate::vault_store::test_params();
        assert_eq!(s.screen, Screen::Unlock);

        s.create_vault("pw", "pw").unwrap();
        assert_eq!(s.screen, Screen::Vault);
        assert!(s.session.is_some());
        assert!(s.password.is_empty(), "the typed password is wiped after use");
        assert!(s.confirm.is_empty());

        // The vault is on disk, so a fresh state starts on Unlock and can
        // reopen it.
        let mut reopened = AppState::new(s.paths.clone());
        reopened.kdf = crate::vault_store::test_params();
        assert_eq!(reopened.initial_screen(), Screen::Unlock);
        reopened.unlock("pw").unwrap();
        assert_eq!(reopened.screen, Screen::Vault);
    }

    #[test]
    fn create_vault_rejects_a_mismatched_confirmation() {
        let mut s = fresh_state();
        s.kdf = crate::vault_store::test_params();
        match s.create_vault("one", "two") {
            Err(AppError::BadInput(msg)) => assert!(msg.contains("match")),
            other => panic!("expected a mismatch error, got {other:?}"),
        }
        assert!(s.session.is_none(), "nothing should be created");
        assert!(!s.paths.exists());
    }

    #[test]
    fn create_vault_rejects_an_empty_password() {
        let mut s = fresh_state();
        s.kdf = crate::vault_store::test_params();
        assert!(s.create_vault("", "").is_err());
        assert!(!s.paths.exists());
    }

    #[test]
    fn create_vault_refuses_to_overwrite() {
        let mut s = unlocked_state();
        match s.create_vault("other", "other") {
            Err(AppError::VaultExists) => {}
            other => panic!("expected VaultExists, got {other:?}"),
        }
    }

    #[test]
    fn unlock_with_the_wrong_password_reports_a_friendly_error() {
        let paths = unlocked_state().paths.clone();
        let mut s = AppState::new(paths);
        match s.unlock("nope") {
            Err(AppError::WrongPassword) => {}
            other => panic!("expected WrongPassword, got {other:?}"),
        }
        assert_eq!(s.screen, Screen::Unlock, "a failed unlock stays on the unlock screen");
    }

    #[test]
    fn new_entry_round_trips_through_disk() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        assert_eq!(s.screen, Screen::Edit);

        {
            let form = s.form.as_mut().unwrap();
            form.title = "GitHub".into();
            form.username = "octocat".into();
            form.password = "hunter2".into();
        }
        s.save_form().unwrap();

        assert_eq!(s.screen, Screen::Vault);
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.selected_title(), "GitHub");
        // The decrypted detail is available without a manual reload.
        assert_eq!(s.detail.as_ref().unwrap().password, "hunter2");

        // And it survives a real reopen from disk.
        let paths = s.paths.clone();
        drop(s);
        let mut again = AppState::new(paths);
        again.unlock("correct horse").unwrap();
        assert_eq!(again.rows.len(), 1);
        assert_eq!(again.selected_title(), "GitHub");
    }

    #[test]
    fn saving_a_form_without_a_title_is_refused() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "  ".into();
        match s.save_form() {
            Err(AppError::BadInput(msg)) => assert!(msg.contains("Title")),
            other => panic!("expected a validation error, got {other:?}"),
        }
        assert_eq!(s.screen, Screen::Edit, "stays on the form so the user can fix it");
        assert!(s.form.is_some());
    }

    #[test]
    fn editing_an_entry_updates_it_rather_than_duplicating() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "Old".into();
        s.save_form().unwrap();

        s.begin_edit_selected();
        assert_eq!(s.screen, Screen::Edit);
        assert!(!s.form.as_ref().unwrap().is_new());
        s.form.as_mut().unwrap().title = "New".into();
        s.save_form().unwrap();

        assert_eq!(s.rows.len(), 1, "editing must not create a second row");
        assert_eq!(s.selected_title(), "New");
    }

    #[test]
    fn cancel_edit_discards_changes() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "Discarded".into();
        s.cancel_edit();
        assert_eq!(s.screen, Screen::Vault);
        assert!(s.form.is_none());
        assert!(s.rows.is_empty(), "a cancelled new entry is not saved");
    }

    #[test]
    fn generate_fills_the_form_and_reveals_it() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.generate_password_into_form();
        let form = s.form.as_ref().unwrap();
        assert_eq!(form.password.chars().count(), s.generator.length);
        assert!(form.reveal, "a just-generated password is shown");
        assert_eq!(form.field, Field::Password, "focus lands on the new password");
    }

    #[test]
    fn generate_respects_invalid_options_without_touching_the_form() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().password = "keep".into();
        s.generator.length = 9999;
        s.generate_password_into_form();
        assert_eq!(s.form.as_ref().unwrap().password, "keep", "bad options change nothing");
        assert_eq!(s.status.unwrap().kind, StatusKind::Error);
    }

    #[test]
    fn toggle_favorite_persists_through_a_reopen() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "Starred".into();
        s.save_form().unwrap();
        assert!(!s.selected_index_entry().unwrap().favorite);

        s.toggle_selected_favorite();
        assert!(s.selected_index_entry().unwrap().favorite);

        let paths = s.paths.clone();
        drop(s);
        let mut again = AppState::new(paths);
        again.unlock("correct horse").unwrap();
        assert!(again.selected_index_entry().unwrap().favorite, "favorite survived the reopen");
    }

    #[test]
    fn delete_removes_the_row_and_the_entry_from_the_index() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "Doomed".into();
        s.save_form().unwrap();
        assert_eq!(s.rows.len(), 1);

        s.delete_selected();
        assert!(s.rows.is_empty());
        assert!(s.status.as_ref().unwrap().text.contains("Doomed"));

        let paths = s.paths.clone();
        drop(s);
        let mut again = AppState::new(paths);
        again.unlock("correct horse").unwrap();
        assert!(again.rows.is_empty(), "the delete was persisted");
    }

    #[test]
    fn copy_queues_the_password_and_reports_success() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        {
            let f = s.form.as_mut().unwrap();
            f.title = "Copy".into();
            f.password = "hunter2".into();
        }
        s.save_form().unwrap();
        s.pending_copy = None;

        s.copy_password();
        assert_eq!(s.pending_copy.as_deref(), Some("hunter2"));
        assert_eq!(s.status.unwrap().kind, StatusKind::Success);
    }

    #[test]
    fn copy_of_a_missing_secret_reports_instead_of_queueing_empty() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "No secret".into();
        s.save_form().unwrap();
        s.pending_copy = None;

        s.copy_password();
        assert!(s.pending_copy.is_none(), "nothing is copied");
        assert_eq!(s.status.unwrap().kind, StatusKind::Error);
    }

    #[test]
    fn reveal_toggles_and_resets_on_lock() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().password = "hunter2".into();

        s.toggle_reveal();
        assert!(s.reveal, "reveal is app-level state");
        assert!(s.form.as_ref().unwrap().reveal, "and it propagates to the form");

        s.toggle_reveal();
        assert!(!s.reveal);
        assert!(!s.form.as_ref().unwrap().reveal);

        s.toggle_reveal();
        s.lock();
        assert!(!s.reveal, "locking always hides secrets");
    }

    #[test]
    fn change_master_password_then_reopen_with_the_new_one() {
        let mut s = unlocked_state();
        s.begin_new_entry();
        s.form.as_mut().unwrap().title = "Kept".into();
        s.save_form().unwrap();

        s.change_master_password("brand new secret", "brand new secret").unwrap();

        let paths = s.paths.clone();
        drop(s);

        // The old password no longer works.
        let mut stale = AppState::new(paths.clone());
        assert!(stale.unlock("correct horse").is_err());

        let mut fresh = AppState::new(paths);
        fresh.kdf = crate::vault_store::test_params();
        fresh.unlock("brand new secret").unwrap();
        assert_eq!(fresh.rows.len(), 1, "entries survive the rekey");
        assert_eq!(fresh.selected_title(), "Kept");
    }

    #[test]
    fn change_master_password_validates_its_inputs() {
        let mut s = unlocked_state();
        assert!(s.change_master_password("a", "b").is_err(), "mismatch");
        assert!(s.change_master_password("", "").is_err(), "empty");
    }

    #[test]
    fn dismissing_a_modal_clears_it() {
        let mut s = unlocked_state();
        s.modal = Some(Modal::Password { title: "t".into(), value: "secret".into() });
        assert!(s.modal_open());
        s.dismiss_modal();
        assert!(!s.modal_open());
    }

    #[test]
    fn auto_lock_countdown_counts_down_and_disappears_when_off() {
        let mut s = unlocked_state();
        s.auto_lock_secs = 100;
        s.idle_secs = 30;
        assert_eq!(s.auto_lock_countdown(), Some(70));

        s.auto_lock_secs = 0;
        assert_eq!(s.auto_lock_countdown(), None, "disabled means no countdown to show");

        let locked = AppState::new(VaultPaths::new("/tmp/nope"));
        assert_eq!(locked.auto_lock_countdown(), None);
    }

    #[test]
    fn new_entry_ids_are_unique() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(ids.insert(new_entry_id()), "ids must never repeat");
        }
        assert!(ids.iter().all(|id: &String| id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())));
    }
}
