use crate::theme::Kind;
use crate::{files, passwords, state, vaults};
use iced::Task;

// ------------------------------------------------------------------ pages ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Vaults,
    Files,
    Passwords,
    Security,
}

impl Page {
    pub(crate) fn title(self) -> &'static str {
        match self {
            Page::Vaults => "Vault",
            Page::Files => "File Containers",
            Page::Passwords => "Password Store",
            Page::Security => "Security & Trust",
        }
    }
    pub(crate) fn epigraph(self) -> &'static str {
        match self {
            Page::Vaults => "Encrypted, verified on-disk stores.",
            Page::Files => "Whole-file sealed containers with hidden filenames.",
            Page::Passwords => "A small vault for encrypted secrets.",
            Page::Security => "What Keres protects, what it does not, and where the audit stands.",
        }
    }
}

// ---------------------------------------------------------------- state -----

#[derive(Debug, Clone, Default)]
pub(crate) struct PageStatus {
    pub(crate) text: String,
    pub(crate) kind: Kind,
}

impl PageStatus {
    fn ok(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            kind: Kind::Ok,
        }
    }
    fn err(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            kind: Kind::Err,
        }
    }
    fn info(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            kind: Kind::Info,
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

pub(crate) struct App {
    pub(crate) state: state::AppState,
    pub(crate) page: Page,
    pub(crate) notice: Vec<(bool, String)>,
    pub(crate) clipboard: Option<arboard::Clipboard>,
    /// UI text scale in percent. 100 is the design size.
    pub(crate) zoom: u16,
    /// Id of the main scroll container, used to reset scroll on navigation.
    pub(crate) scroll_id: iced::widget::Id,

    pub(crate) vt_name: String,
    pub(crate) vt_password: String,
    pub(crate) vt_confirm_password: String,
    pub(crate) vt_new_password: String,
    pub(crate) vt_status: PageStatus,
    pub(crate) vt_count: String,
    pub(crate) vt_entries: Vec<(String, String)>,
    pub(crate) vt_status_info: Option<vaults::VaultStatus>,
    pub(crate) vt_needs_migration: bool,
    pub(crate) vt_known: Vec<String>,
    pub(crate) vt_padding: vaults::PaddingPreset,
    pub(crate) vt_kdf: vaults::KdfPreset,
    pub(crate) vt_rename_from: String,
    pub(crate) vt_rename_to: String,
    pub(crate) vt_recovery_code: String,
    pub(crate) vt_recovery_input: String,
    pub(crate) vt_slot_password: String,
    pub(crate) vt_slots: Vec<String>,
    pub(crate) vt_erase_name: String,
    pub(crate) vt_erase_confirm: String,

    pub(crate) fl_password: String,
    pub(crate) fl_input: String,
    pub(crate) fl_output: String,
    pub(crate) fl_status: PageStatus,

    pub(crate) pw_password: String,
    pub(crate) pw_status: PageStatus,
    pub(crate) pw_name: String,
    pub(crate) pw_user: String,
    pub(crate) pw_len: u8,
    pub(crate) pw_symbols: bool,
    pub(crate) pw_generated: String,
    pub(crate) pw_entries: Vec<(String, String, String)>,
}

impl Default for App {
    fn default() -> Self {
        let state = state::AppState::default();
        let vt_known = vaults::list_vault_names(&state.vaults);
        Self {
            state,
            page: Page::Vaults,
            notice: Vec::new(),
            clipboard: None,
            zoom: crate::util::load_zoom(),
            scroll_id: iced::widget::Id::unique(),
            vt_name: String::new(),
            vt_password: String::new(),
            vt_confirm_password: String::new(),
            vt_new_password: String::new(),
            vt_status: PageStatus::default(),
            vt_count: String::new(),
            vt_entries: Vec::new(),
            vt_status_info: None,
            vt_needs_migration: false,
            vt_known,
            vt_padding: vaults::PaddingPreset::default(),
            vt_kdf: vaults::KdfPreset::default(),
            vt_rename_from: String::new(),
            vt_rename_to: String::new(),
            vt_recovery_code: String::new(),
            vt_recovery_input: String::new(),
            vt_slot_password: String::new(),
            vt_slots: Vec::new(),
            vt_erase_name: String::new(),
            vt_erase_confirm: String::new(),
            fl_password: String::new(),
            fl_input: String::new(),
            fl_output: String::new(),
            fl_status: PageStatus::default(),
            pw_password: String::new(),
            pw_status: PageStatus::default(),
            pw_name: String::new(),
            pw_user: String::new(),
            pw_len: 24,
            pw_symbols: true,
            pw_generated: String::new(),
            pw_entries: Vec::new(),
        }
    }
}

// -------------------------------------------------------------- messages ----

#[derive(Debug, Clone)]
pub(crate) enum Message {
    Nav(Page),
    ZoomIn,
    ZoomOut,
    ZoomReset,

    VtName(String),
    VtPassword(String),
    VtConfirmPassword(String),
    VtNewPassword(String),
    VtPadding(vaults::PaddingPreset),
    VtKdf(vaults::KdfPreset),
    VtSelect(String),
    VtCreate,
    VtUnlock,
    VtMigrate,
    VtLock,
    VtAddFile,
    VtAddDir,
    VtReplace(String),
    VtRenameFrom(String),
    VtRenameTo(String),
    VtRename,
    VtExtract(String),
    VtRemove(String),
    VtVerify,
    VtChangePassword,
    VtCreateRecovery,
    VtCopyRecovery,
    VtRecoveryInput(String),
    VtRecover,
    VtSlotPassword(String),
    VtAddSlot,
    VtRemoveSlot(String),
    VtRotate,
    VtEraseName(String),
    VtEraseConfirm(String),
    VtErase,

    FlPassword(String),
    FlInput(String),
    FlOutput(String),
    FlPickInput,
    FlPickOutput,
    FlEncrypt,
    FlDecrypt,

    PwPassword(String),
    PwCreate,
    PwUnlock,
    PwLock,
    PwName(String),
    PwUser(String),
    PwLen(u8),
    PwSymbols(bool),
    PwGenerate,
    PwSave,
    PwCopy(String),
    PwRemove(String),
}

impl App {
    fn copy(&mut self, s: String) {
        if self.clipboard.is_none() {
            match arboard::Clipboard::new() {
                Ok(cb) => self.clipboard = Some(cb),
                Err(e) => {
                    self.notice.push((false, format!("clipboard: {e}")));
                    return;
                }
            }
        }
        let result = self
            .clipboard
            .as_mut()
            .expect("clipboard initialised above")
            .set_text(s);
        match result {
            Ok(()) => self.notice.push((true, "copied to clipboard".to_string())),
            Err(e) => self.notice.push((false, format!("clipboard: {e}"))),
        }
    }

    fn vaults_refresh(&mut self) {
        self.vt_entries = vaults::list_entries(&self.state.vaults).unwrap_or_default();
        self.vt_status_info = vaults::status(&self.state.vaults);
        self.vt_slots = vaults::keyslots(&self.state.vaults).unwrap_or_default();
        self.vt_known = vaults::list_vault_names(&self.state.vaults);
        if self.state.vaults.open.is_some() {
            self.vt_count = format!("{} entries", self.vt_entries.len());
        } else {
            self.vt_count = String::new();
        }
    }

    fn passwords_refresh(&mut self) {
        self.pw_entries = passwords::list_entries(&self.state.passwords).unwrap_or_default();
    }

    pub(crate) fn subscription(&self) -> iced::Subscription<Message> {
        iced::event::listen_with(|event, status, _window| {
            if status != iced::event::Status::Ignored {
                return None;
            }
            match event {
                iced::event::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key,
                    modifiers,
                    ..
                }) => {
                    if !modifiers.command() {
                        return None;
                    }
                    match key.as_ref() {
                        iced::keyboard::Key::Character("1") => Some(Message::Nav(Page::Vaults)),
                        iced::keyboard::Key::Character("2") => Some(Message::Nav(Page::Passwords)),
                        iced::keyboard::Key::Character("3") => Some(Message::Nav(Page::Files)),
                        iced::keyboard::Key::Character("4") => Some(Message::Nav(Page::Security)),
                        iced::keyboard::Key::Character("+")
                        | iced::keyboard::Key::Character("=") => Some(Message::ZoomIn),
                        iced::keyboard::Key::Character("-") => Some(Message::ZoomOut),
                        iced::keyboard::Key::Character("0") => Some(Message::ZoomReset),
                        _ => None,
                    }
                }
                _ => None,
            }
        })
    }

    pub(crate) fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Nav(page) => {
                self.page = page;
                self.notice.clear();
                return iced::widget::operation::scroll_to(
                    self.scroll_id.clone(),
                    iced::widget::operation::AbsoluteOffset::<Option<f32>> {
                        x: None,
                        y: Some(0.0),
                    },
                );
            }
            Message::ZoomIn => {
                self.zoom = (self.zoom + 10).min(300);
                crate::util::save_zoom(self.zoom);
            }
            Message::ZoomOut => {
                self.zoom = self.zoom.saturating_sub(10).max(80);
                crate::util::save_zoom(self.zoom);
            }
            Message::ZoomReset => {
                self.zoom = 115;
                crate::util::save_zoom(self.zoom);
            }

            Message::VtName(s) => {
                self.vt_name = s;
                self.vt_needs_migration = false;
            }
            Message::VtPassword(s) => self.vt_password = s,
            Message::VtConfirmPassword(s) => self.vt_confirm_password = s,
            Message::VtNewPassword(s) => self.vt_new_password = s,
            Message::VtPadding(p) => self.vt_padding = p,
            Message::VtKdf(k) => self.vt_kdf = k,
            Message::VtSelect(name) => {
                self.vt_name = name;
                self.vt_needs_migration = false;
            }
            Message::VtCreate => {
                match vaults::create_vault_with_options(
                    &mut self.state.vaults,
                    &self.vt_name,
                    &self.vt_password,
                    &self.vt_confirm_password,
                    self.vt_padding,
                    self.vt_kdf,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_password.clear();
                        self.vt_confirm_password.clear();
                        self.vt_needs_migration = false;
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtUnlock => {
                match vaults::unlock_vault(&mut self.state.vaults, &self.vt_name, &self.vt_password)
                {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_password.clear();
                        self.vt_needs_migration = false;
                        self.vaults_refresh();
                    }
                    Err(keres::Error::MigrationRequired) => {
                        self.vt_needs_migration = true;
                        self.vt_status = PageStatus::info(
                            "legacy vault detected — migrate it in place to the current format",
                        );
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtMigrate => {
                match vaults::migrate_vault(
                    &mut self.state.vaults,
                    &self.vt_name,
                    &self.vt_password,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_password.clear();
                        self.vt_needs_migration = false;
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("migration failed: {e}"));
                    }
                }
            }
            Message::VtLock => match vaults::lock_vault(&mut self.state.vaults) {
                Ok(msg) => {
                    self.vt_status = PageStatus::info(msg);
                    self.vaults_refresh();
                }
                Err(e) => {
                    self.vt_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::VtAddFile => match vaults::add_file(&mut self.state.vaults) {
                Ok(msg) => {
                    self.vt_status = PageStatus::ok(msg);
                    self.vaults_refresh();
                }
                Err(e) => {
                    self.vt_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::VtAddDir => match vaults::add_dir(&mut self.state.vaults) {
                Ok(msg) => {
                    self.vt_status = PageStatus::ok(msg);
                    self.vaults_refresh();
                }
                Err(e) => {
                    self.vt_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::VtReplace(name) => {
                match vaults::replace_entry(&mut self.state.vaults, &name) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtRenameFrom(s) => self.vt_rename_from = s,
            Message::VtRenameTo(s) => self.vt_rename_to = s,
            Message::VtRename => {
                match vaults::rename_entry(
                    &mut self.state.vaults,
                    &self.vt_rename_from,
                    &self.vt_rename_to,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_rename_from.clear();
                        self.vt_rename_to.clear();
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtExtract(name) => match vaults::extract_entry(&self.state.vaults, &name) {
                Ok(msg) => self.vt_status = PageStatus::ok(msg),
                Err(e) => {
                    self.vt_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::VtRemove(name) => match vaults::remove_entry(&mut self.state.vaults, &name) {
                Ok(msg) => {
                    self.vt_status = PageStatus::ok(msg);
                    self.vaults_refresh();
                }
                Err(e) => {
                    self.vt_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::VtVerify => {
                match vaults::verify_vault(&mut self.state.vaults, &self.vt_password) {
                    Ok(msg) if msg.contains("OK") => self.vt_status = PageStatus::ok(msg),
                    Ok(msg) => self.vt_status = PageStatus::info(msg),
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtChangePassword => {
                match vaults::change_vault_password(
                    &mut self.state.vaults,
                    &self.vt_password,
                    &self.vt_new_password,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_new_password.clear();
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtCreateRecovery => {
                match vaults::create_recovery_kit(&mut self.state.vaults, &self.vt_password) {
                    Ok(code) => {
                        self.vt_recovery_code = code;
                        self.vt_status = PageStatus::ok(
                            "Recovery kit created — copy the code somewhere offline",
                        );
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtCopyRecovery => {
                if !self.vt_recovery_code.is_empty() {
                    self.copy(self.vt_recovery_code.clone());
                }
            }
            Message::VtRecoveryInput(s) => self.vt_recovery_input = s,
            Message::VtRecover => {
                match vaults::recover_vault(
                    &mut self.state.vaults,
                    &self.vt_name,
                    &self.vt_recovery_input,
                    &self.vt_new_password,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_recovery_input.clear();
                        self.vt_new_password.clear();
                        self.vt_needs_migration = false;
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("recovery failed: {e}"));
                    }
                }
            }
            Message::VtSlotPassword(s) => self.vt_slot_password = s,
            Message::VtAddSlot => {
                match vaults::add_keyslot(
                    &mut self.state.vaults,
                    &self.vt_password,
                    &self.vt_slot_password,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_slot_password.clear();
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtRemoveSlot(id) => {
                match vaults::remove_keyslot(&mut self.state.vaults, &id, &self.vt_password) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::VtRotate => {
                match vaults::rotate_vault(
                    &mut self.state.vaults,
                    &self.vt_password,
                    &self.vt_new_password,
                ) {
                    Ok(msg) => {
                        self.vt_status = PageStatus::ok(msg);
                        self.vt_password.clear();
                        self.vt_new_password.clear();
                        self.vaults_refresh();
                    }
                    Err(e) => {
                        self.vt_status = PageStatus::err(format!("rotation failed: {e}"));
                    }
                }
            }
            Message::VtEraseName(s) => self.vt_erase_name = s,
            Message::VtEraseConfirm(s) => self.vt_erase_confirm = s,
            Message::VtErase => {
                if self.vt_erase_confirm != self.vt_erase_name {
                    self.vt_status =
                        PageStatus::err("type the entry name exactly to confirm crypto-erasure");
                } else {
                    match vaults::erase_entry(
                        &mut self.state.vaults,
                        &self.vt_erase_name,
                        &self.vt_new_password,
                    ) {
                        Ok(msg) => {
                            self.vt_status = PageStatus::ok(msg);
                            self.vt_erase_name.clear();
                            self.vt_erase_confirm.clear();
                            self.vt_new_password.clear();
                            self.vaults_refresh();
                        }
                        Err(e) => {
                            self.vt_status = PageStatus::err(format!("erase failed: {e}"));
                        }
                    }
                }
            }

            Message::FlPassword(s) => self.fl_password = s,
            Message::FlInput(s) => self.fl_input = s,
            Message::FlOutput(s) => self.fl_output = s,
            Message::FlPickInput => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Select input file")
                    .pick_file()
                {
                    self.fl_input = p.display().to_string();
                }
            }
            Message::FlPickOutput => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Select output file")
                    .save_file()
                {
                    self.fl_output = p.display().to_string();
                }
            }
            Message::FlEncrypt => {
                let input = std::path::PathBuf::from(&self.fl_input);
                let output = if self.fl_output.is_empty() {
                    None
                } else {
                    Some(std::path::PathBuf::from(&self.fl_output))
                };
                match files::encrypt_file(&self.fl_password, &input, output.as_deref()) {
                    Ok((cipher, msg)) => {
                        self.fl_status = PageStatus::ok(msg);
                        if self.fl_output.is_empty() {
                            self.fl_output = cipher.display().to_string();
                        }
                    }
                    Err(e) => {
                        self.fl_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::FlDecrypt => {
                let input = std::path::PathBuf::from(&self.fl_input);
                let output = if self.fl_output.is_empty() {
                    files::default_decrypt_output(&input)
                } else {
                    std::path::PathBuf::from(&self.fl_output)
                };
                match files::decrypt_file(&self.fl_password, &input, &output) {
                    Ok((_, _, msg)) => {
                        self.fl_status = PageStatus::ok(msg);
                    }
                    Err(e) => {
                        self.fl_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }

            Message::PwPassword(s) => self.pw_password = s,
            Message::PwCreate => {
                match passwords::create(&mut self.state.passwords, &self.pw_password) {
                    Ok(msg) => {
                        self.pw_status = PageStatus::ok(msg);
                        self.passwords_refresh();
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::PwUnlock => {
                match passwords::unlock(&mut self.state.passwords, &self.pw_password) {
                    Ok(msg) => {
                        self.pw_status = PageStatus::ok(msg);
                        self.passwords_refresh();
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::PwLock => match passwords::lock(&mut self.state.passwords) {
                Ok(msg) => {
                    self.pw_status = PageStatus::info(msg);
                    self.passwords_refresh();
                }
                Err(e) => {
                    self.pw_status = PageStatus::err(format!("failed: {e}"));
                }
            },
            Message::PwName(s) => self.pw_name = s,
            Message::PwUser(s) => self.pw_user = s,
            Message::PwLen(n) => self.pw_len = n,
            Message::PwSymbols(b) => self.pw_symbols = b,
            Message::PwGenerate => {
                match passwords::generate(self.pw_len as usize, self.pw_symbols) {
                    Ok(p) => {
                        self.pw_generated = p;
                        self.pw_status = PageStatus::ok(format!(
                            "generated · {} chars{}",
                            self.pw_len,
                            if self.pw_symbols { " · symbols" } else { "" }
                        ));
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::PwSave => {
                match passwords::save_entry(
                    &mut self.state.passwords,
                    &self.pw_name,
                    &self.pw_user,
                    &self.pw_generated,
                ) {
                    Ok(msg) => {
                        self.pw_status = PageStatus::ok(msg);
                        self.passwords_refresh();
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::PwCopy(entry) => {
                match passwords::entry_password(&self.state.passwords, &entry) {
                    Ok(secret) => {
                        self.copy(secret);
                        match self.notice.last() {
                            Some((true, _)) => {
                                self.pw_status = PageStatus::ok(format!(
                                    "Copied password for '{entry}' to clipboard"
                                ));
                            }
                            Some((false, msg)) => {
                                self.pw_status = PageStatus::err(format!("failed: {msg}"));
                            }
                            None => {}
                        }
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
            Message::PwRemove(entry) => {
                match passwords::remove_entry(&mut self.state.passwords, &entry) {
                    Ok(msg) => {
                        self.pw_status = PageStatus::ok(msg);
                        self.passwords_refresh();
                    }
                    Err(e) => {
                        self.pw_status = PageStatus::err(format!("failed: {e}"));
                    }
                }
            }
        }
        Task::none()
    }

    // ------------------------------------------------------------------ view
}
