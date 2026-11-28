use crate::app::{App, Message};
use crate::theme;
use crate::ui::widgets::{
    btn_g, btn_p, btn_red, btn_tiny, card, field, hline, input, panel, status_line,
};
use crate::vaults;
use iced::widget::{checkbox, column, container, pick_list, row, slider, text, Space};
use iced::Length::Fill;
use iced::{Element, Length};

impl App {
    pub(crate) fn page_vaults(&self) -> Element<'_, Message> {
        let open = self.state.vaults.open.is_some();

        // ---------------------------------------------------------- dashboard
        let dashboard: Element<'_, Message> = match &self.vt_status_info {
            Some(st) => column![
                row![
                    text(&st.name).size(theme::sz(15.0)).color(theme::TEXT),
                    Space::new().width(Fill),
                    text(if st.unlocked { "unlocked" } else { "locked" })
                        .size(theme::sz(11.0))
                        .color(if st.unlocked {
                            theme::GREEN
                        } else {
                            theme::ACCENT
                        }),
                ]
                .align_y(iced::Alignment::Center),
                text(st.path.display().to_string())
                    .size(theme::sz(10.0))
                    .color(theme::FAINT),
                hline(),
                row![
                    stat("entries", st.entries.to_string()),
                    stat("index", format!("g{} · {} rec", st.generation, st.records)),
                    stat("padding", st.padding.clone()),
                    stat("keyslots", st.keyslots.to_string()),
                    stat(
                        "recovery",
                        if st.recovery_kit {
                            "present".to_string()
                        } else {
                            "none".to_string()
                        },
                    ),
                ]
                .spacing(20),
            ]
            .spacing(8)
            .into(),
            None => column![
                text("No vault is open")
                    .size(theme::sz(13.0))
                    .color(theme::TEXT),
                text("Create a vault or unlock one of the vaults on disk below.")
                    .size(theme::sz(11.0))
                    .color(theme::FAINT),
            ]
            .spacing(6)
            .into(),
        };

        let known: Element<'_, Message> = if self.vt_known.is_empty() {
            text("no vaults on disk yet")
                .size(theme::sz(11.0))
                .color(theme::FAINT)
                .into()
        } else {
            row(self
                .vt_known
                .iter()
                .map(|name| btn_tiny(name, Message::VtSelect(name.clone()))))
            .spacing(6)
            .into()
        };

        let dashboard = column![dashboard, hline(), known].spacing(10);

        // ------------------------------------------------------------ entries
        let entries: Element<'_, Message> = if open {
            if self.vt_entries.is_empty() {
                text("vault is empty — add files or folders")
                    .size(theme::sz(12.0))
                    .color(theme::FAINT)
                    .into()
            } else {
                let rows: Vec<Element<'_, Message>> = self
                    .vt_entries
                    .iter()
                    .map(|(name, display)| {
                        row![
                            text(display).size(theme::sz(12.0)).color(theme::TEXT),
                            Space::new().width(Fill),
                            btn_tiny("extract", Message::VtExtract(name.clone())),
                            btn_tiny("replace", Message::VtReplace(name.clone())),
                            btn_red("rm", Message::VtRemove(name.clone())),
                        ]
                        .align_y(iced::Alignment::Center)
                        .spacing(8)
                        .into()
                    })
                    .collect();
                column(rows).spacing(8).into()
            }
        } else {
            text("vault locked — unlock to browse entries")
                .size(theme::sz(12.0))
                .color(theme::FAINT)
                .into()
        };

        let entry_actions: Element<'_, Message> = if open {
            column![
                row![
                    input(
                        "current name",
                        &self.vt_rename_from,
                        Message::VtRenameFrom,
                        false,
                    )
                    .width(Fill),
                    input("new name", &self.vt_rename_to, Message::VtRenameTo, false).width(Fill),
                    btn_tiny("rename", Message::VtRename),
                ]
                .spacing(8),
                row![
                    btn_tiny("add file", Message::VtAddFile),
                    btn_tiny("add folder", Message::VtAddDir),
                    btn_red("verify integrity", Message::VtVerify),
                ]
                .spacing(8),
            ]
            .spacing(10)
            .into()
        } else {
            Space::new().into()
        };

        // ------------------------------------------------------------- access
        let migrate: Element<'_, Message> = if self.vt_needs_migration {
            column![
                text(
                    "This vault predates the current manifest. Migration rewrites it in place; back up the vault directory first."
                )
                .size(theme::sz(11.0))
                .color(theme::ACCENT),
                btn_red("migrate vault", Message::VtMigrate),
            ]
            .spacing(8)
            .into()
        } else {
            Space::new().into()
        };

        let change_password: Element<'_, Message> = if open {
            column![
                hline(),
                field(
                    "new passphrase",
                    input(
                        "new passphrase",
                        &self.vt_new_password,
                        Message::VtNewPassword,
                        true,
                    ),
                ),
                btn_tiny("change passphrase", Message::VtChangePassword),
            ]
            .spacing(10)
            .into()
        } else {
            Space::new().into()
        };

        let access = column![
            field(
                "vault name",
                input("vault name", &self.vt_name, Message::VtName, false)
            ),
            field(
                "passphrase",
                input(
                    "vault passphrase",
                    &self.vt_password,
                    Message::VtPassword,
                    true,
                )
                .on_submit(Message::VtUnlock),
            ),
            field(
                "confirm passphrase",
                input(
                    "repeat for create",
                    &self.vt_confirm_password,
                    Message::VtConfirmPassword,
                    true,
                )
            ),
            row![
                btn_p("create", Message::VtCreate),
                btn_g("unlock", Message::VtUnlock),
                btn_g("lock", Message::VtLock),
            ]
            .spacing(8),
            migrate,
            change_password,
        ]
        .spacing(12);

        let create_options = column![
            field(
                "size padding",
                pick_list(
                    &vaults::PaddingPreset::ALL[..],
                    Some(self.vt_padding),
                    Message::VtPadding,
                )
                .style(theme::pick_list_style)
                .menu_style(theme::menu_style)
                .text_size(theme::sz(13.0))
                .padding([8, 12]),
            ),
            field(
                "argon2id cost",
                pick_list(
                    &vaults::KdfPreset::ALL[..],
                    Some(self.vt_kdf),
                    Message::VtKdf,
                )
                .style(theme::pick_list_style)
                .menu_style(theme::menu_style)
                .text_size(theme::sz(13.0))
                .padding([8, 12]),
            ),
            text(
                "Padding hides exact plaintext sizes at the cost of storage. The KDF cost is stored in the keyslot and inherited by later slot changes."
            )
            .size(theme::sz(11.0))
            .color(theme::FAINT),
        ]
        .spacing(12);

        // ----------------------------------------------------------- recovery
        let recovery_code: Element<'_, Message> = if self.vt_recovery_code.is_empty() {
            Space::new().into()
        } else {
            column![
                card(
                    text(&self.vt_recovery_code)
                        .size(theme::sz(12.0))
                        .color(theme::TEXT)
                ),
                row![btn_tiny("copy code", Message::VtCopyRecovery)].spacing(8),
            ]
            .spacing(8)
            .into()
        };

        let recovery = column![
            text(
                "Create a one-time code that resets the passphrase if you forget it. It is shown once; store it offline."
            )
            .size(theme::sz(11.0))
            .color(theme::FAINT),
            row![
                input(
                    "authorizing passphrase",
                    &self.vt_password,
                    Message::VtPassword,
                    true,
                )
                .width(Fill),
                btn_tiny("create kit", Message::VtCreateRecovery),
            ]
            .spacing(8),
            recovery_code,
            hline(),
            text("Recover a closed vault").size(theme::sz(11.0)).color(theme::DIM),
            input(
                "recovery code",
                &self.vt_recovery_input,
                Message::VtRecoveryInput,
                false,
            ),
            input(
                "new passphrase",
                &self.vt_new_password,
                Message::VtNewPassword,
                true,
            ),
            btn_red("recover vault", Message::VtRecover),
        ]
        .spacing(10);

        // ------------------------------------------------------------ keyslots
        let slot_rows: Element<'_, Message> = if self.vt_slots.is_empty() {
            text("no keyslots visible (vault closed or legacy config)")
                .size(theme::sz(11.0))
                .color(theme::FAINT)
                .into()
        } else {
            column(
                self.vt_slots
                    .iter()
                    .map(|id| {
                        row![
                            text(id).size(theme::sz(11.0)).color(theme::TEXT),
                            Space::new().width(Fill),
                            btn_red("revoke", Message::VtRemoveSlot(id.clone())),
                        ]
                        .align_y(iced::Alignment::Center)
                        .spacing(8)
                        .into()
                    })
                    .collect::<Vec<Element<'_, Message>>>(),
            )
            .spacing(6)
            .into()
        };

        let keyslots = column![
            text(
                "Each keyslot is an independent passphrase for the same master key. Removing a slot revokes that passphrase."
            )
            .size(theme::sz(11.0))
            .color(theme::FAINT),
            slot_rows,
            row![
                input(
                    "new slot passphrase",
                    &self.vt_slot_password,
                    Message::VtSlotPassword,
                    true,
                )
                .width(Fill),
                btn_tiny("add slot", Message::VtAddSlot),
            ]
            .spacing(8),
            text("Authorize with a passphrase from a slot that will remain.")
                .size(theme::sz(10.0))
                .color(theme::FAINT),
        ]
        .spacing(10);

        // ------------------------------------------------------------- advanced
        let advanced = column![
            text(
                "Rotation re-encrypts every entry under a fresh master key. Extra keyslots and the recovery kit are dropped; the vault ends locked."
            )
            .size(theme::sz(11.0))
            .color(theme::FAINT),
            row![
                input(
                    "current passphrase",
                    &self.vt_password,
                    Message::VtPassword,
                    true,
                )
                .width(Fill),
                input(
                    "new passphrase",
                    &self.vt_new_password,
                    Message::VtNewPassword,
                    true,
                )
                .width(Fill),
                btn_red("rotate", Message::VtRotate),
            ]
            .spacing(8),
            hline(),
            text(
                "Crypto-erasure removes one entry and rotates every survivor. It is forward-looking: copies captured earlier cannot be revoked."
            )
            .size(theme::sz(11.0))
            .color(theme::RED),
            row![
                input(
                    "entry to erase",
                    &self.vt_erase_name,
                    Message::VtEraseName,
                    false,
                )
                .width(Fill),
                input(
                    "type the name again",
                    &self.vt_erase_confirm,
                    Message::VtEraseConfirm,
                    false,
                )
                .width(Fill),
                btn_red("erase", Message::VtErase),
            ]
            .spacing(8),
        ]
        .spacing(10);

        let body = column![
            row![
                panel("dashboard", dashboard).width(Fill),
                panel(
                    "entries",
                    column![
                        row![
                            text("entries").size(theme::sz(11.0)).color(theme::FAINT),
                            Space::new().width(Fill),
                            text(&self.vt_count).size(theme::sz(11.0)).color(theme::DIM),
                        ],
                        entries,
                        entry_actions,
                    ]
                    .spacing(12)
                )
                .width(Fill),
            ]
            .spacing(20),
            row![
                panel("open or create", access).width(Fill),
                panel("create options", create_options).width(Fill),
            ]
            .spacing(20),
            row![
                panel("recovery kit", recovery).width(Fill),
                panel("keyslots", keyslots).width(Fill),
            ]
            .spacing(20),
            panel("rotate & erase", advanced),
            status_line(&self.vt_status),
        ]
        .spacing(18);

        page_root(self.page.title(), self.page.epigraph(), body)
    }

    pub(crate) fn page_files(&self) -> Element<'_, Message> {
        page_root(
            self.page.title(),
            self.page.epigraph(),
            column![
                panel(
                    "passphrase",
                    column![card(input(
                        "passphrase",
                        &self.fl_password,
                        Message::FlPassword,
                        true
                    )),]
                ),
                panel(
                    "input",
                    column![card(
                        row![
                            input(
                                "path to plaintext or container",
                                &self.fl_input,
                                Message::FlInput,
                                false,
                            )
                            .width(Fill),
                            btn_tiny("browse…", Message::FlPickInput),
                        ]
                        .align_y(iced::Alignment::Center)
                        .spacing(8)
                    ),]
                ),
                panel(
                    "output",
                    column![card(
                        row![
                            input(
                                "output path (optional)",
                                &self.fl_output,
                                Message::FlOutput,
                                false,
                            )
                            .width(Fill),
                            btn_tiny("browse…", Message::FlPickOutput),
                        ]
                        .align_y(iced::Alignment::Center)
                        .spacing(8)
                    ),]
                ),
                row![
                    btn_p("seal file", Message::FlEncrypt),
                    btn_g("open file", Message::FlDecrypt),
                ]
                .spacing(8),
                status_line(&self.fl_status),
            ]
            .spacing(14),
        )
    }

    pub(crate) fn page_passwords(&self) -> Element<'_, Message> {
        let open = self.state.passwords.vault.is_some();

        let entries: Element<'_, Message> = if open {
            if self.pw_entries.is_empty() {
                text("no entries yet — generate one below")
                    .size(theme::sz(12.0))
                    .color(theme::FAINT)
                    .into()
            } else {
                let rows: Vec<Element<'_, Message>> = self
                    .pw_entries
                    .iter()
                    .map(|(entry, display, username)| {
                        row![
                            text(display).size(theme::sz(12.0)).color(theme::TEXT),
                            text(format!(" · {username}"))
                                .size(theme::sz(11.0))
                                .color(theme::DIM),
                            Space::new().width(Fill),
                            btn_tiny("copy", Message::PwCopy(entry.clone())),
                            btn_red("rm", Message::PwRemove(entry.clone())),
                        ]
                        .align_y(iced::Alignment::Center)
                        .spacing(8)
                        .into()
                    })
                    .collect();
                column(rows).spacing(8).into()
            }
        } else {
            text("vault locked — unlock to browse entries")
                .size(theme::sz(12.0))
                .color(theme::FAINT)
                .into()
        };

        page_root(
            self.page.title(),
            self.page.epigraph(),
            column![
                row![
                    panel(
                        "access",
                        column![
                            field(
                                "master passphrase",
                                input(
                                    "master passphrase",
                                    &self.pw_password,
                                    Message::PwPassword,
                                    true,
                                )
                                .on_submit(Message::PwUnlock)
                            ),
                            row![
                                btn_p("create", Message::PwCreate),
                                btn_g("unlock", Message::PwUnlock),
                                btn_g("lock", Message::PwLock),
                            ]
                            .spacing(8),
                        ]
                        .spacing(12)
                    )
                    .width(Fill),
                    panel(
                        "generator",
                        column![
                            field(
                                "length",
                                row![
                                    slider(8..=64, self.pw_len, Message::PwLen)
                                        .style(theme::slider_style)
                                        .width(Fill),
                                    text(format!("  {}  ", self.pw_len))
                                        .size(theme::sz(12.0))
                                        .color(theme::ACCENT),
                                ]
                                .align_y(iced::Alignment::Center)
                            ),
                            card(
                                checkbox(self.pw_symbols)
                                    .label("include symbols")
                                    .style(theme::checkbox_style)
                                    .text_size(theme::sz(12.0))
                                    .on_toggle(Message::PwSymbols)
                            ),
                            btn_g("generate", Message::PwGenerate),
                            card(
                                text(if self.pw_generated.is_empty() {
                                    "generated password appears here"
                                } else {
                                    &self.pw_generated
                                })
                                .size(theme::sz(12.0))
                                .color(
                                    if self.pw_generated.is_empty() {
                                        theme::FAINT
                                    } else {
                                        theme::TEXT
                                    }
                                )
                            ),
                        ]
                        .spacing(12)
                    )
                    .width(Fill),
                ]
                .spacing(20),
                panel(
                    "save entry",
                    column![
                        card(
                            row![
                                input("service", &self.pw_name, Message::PwName, false).width(Fill),
                                input("username", &self.pw_user, Message::PwUser, false)
                                    .width(Fill),
                            ]
                            .align_y(iced::Alignment::Center)
                            .spacing(8)
                        ),
                        btn_p("save", Message::PwSave),
                    ]
                    .spacing(12)
                ),
                panel("entries", column![card(entries)]),
                status_line(&self.pw_status),
            ]
            .spacing(14),
        )
    }

    pub(crate) fn page_security(&self) -> Element<'_, Message> {
        let versions = column![
            trust_item("library", format!("keres {}", keres::VERSION)),
            trust_item(
                "desktop",
                format!("keres-desktop {}", env!("CARGO_PKG_VERSION"))
            ),
            trust_item("format", "container v2 · config v3 · manifest v3"),
        ]
        .spacing(12);

        let audit = column![
            text("NOT INDEPENDENTLY AUDITED")
                .size(theme::sz(12.0))
                .color(theme::RED),
            text(
                "Internal review, fuzzing, and a large test suite are not a substitute for an external cryptography and security review. Do not treat this build as audited."
            )
            .size(theme::sz(11.0))
            .color(theme::DIM),
            text(
                "The threat model, known limitations, and the prioritized audit scope live in docs/src/security.md."
            )
            .size(theme::sz(11.0))
            .color(theme::FAINT),
        ]
        .spacing(8);

        let guarantees = column![
            trust_item(
                "Confidentiality at rest",
                "File contents, names, and directory structure are encrypted. The adversary is assumed to have the storage medium, not a running unlocked process."
            ),
            trust_item(
                "Tamper evidence",
                "AEAD tags, an authenticated index, and per-entry content hashes detect modification, truncation, and blob substitution before plaintext is released."
            ),
            trust_item(
                "Crash safety",
                "Config writes are atomic and rotation is journaled, so an interrupted operation leaves a readable vault rather than a half-written one."
            ),
            trust_item(
                "Small surface",
                "One container format, one chunk engine, no async runtime, and no network code in the library."
            ),
        ]
        .spacing(12);

        let limitations = column![
            trust_item(
                "No key commitment",
                "AES-GCM is not key-committing. Keres limits the impact with single-key containers and a structured authenticated trailer, but there is no formal commitment tag yet."
            ),
            trust_item(
                "No memory locking",
                "Keys can be swapped or captured in a core dump if the operating system allows it. Locking drops the handle and zeroizes library key material, but cannot control the OS."
            ),
            trust_item(
                "Size leakage",
                "Ciphertext length reveals plaintext length unless padding is enabled. Padding is opt-in and never hides access patterns or timestamps."
            ),
            trust_item(
                "Whole-vault rollback",
                "Restoring an older valid vault directory is not detected. Content hashes catch a substituted blob, not a coherent older snapshot."
            ),
            trust_item(
                "Knowledge factors only",
                "Passwords, keyslots, and recovery codes are all knowledge factors. There is no hardware token or multi-party split."
            ),
        ]
        .spacing(12);

        let app = column![
            trust_item(
                "No plaintext temp files",
                "The password store writes and reads entries through Keres reader/writer APIs, so secrets stay in process memory instead of a temporary file."
            ),
            trust_item(
                "Local only",
                "The app opens local paths and never uploads vault contents. Network storage is outside the trust boundary."
            ),
            trust_item(
                "Explicit dangerous actions",
                "Rotation and crypto-erasure are separated from everyday entry actions and require the current passphrase; erasure also requires typing the entry name."
            ),
            trust_item(
                "A reference consumer",
                "The GUI demonstrates the embedding patterns documented in the book. It is not a security boundary and does not replace the library's review."
            ),
        ]
        .spacing(12);

        page_root(
            self.page.title(),
            self.page.epigraph(),
            column![
                row![
                    panel("versions", versions).width(Fill),
                    panel("audit status", audit).width(Fill),
                ]
                .spacing(20),
                panel("security goals", guarantees),
                panel("known limitations", limitations),
                panel("what this application does", app),
            ]
            .spacing(14),
        )
    }
}

fn trust_item<'a>(title: impl Into<String>, body: impl Into<String>) -> Element<'a, Message> {
    column![
        text(title.into()).size(theme::sz(12.0)).color(theme::TEXT),
        text(body.into()).size(theme::sz(11.0)).color(theme::DIM),
    ]
    .spacing(3)
    .into()
}

fn stat<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    column![
        text(label).size(theme::sz(10.0)).color(theme::FAINT),
        text(value).size(theme::sz(13.0)).color(theme::TEXT),
    ]
    .spacing(2)
    .into()
}

fn page_root<'a>(
    title: &'a str,
    epigraph: &'a str,
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    container(
        column![
            row![
                text("❯").size(theme::sz(16.0)).color(theme::ACCENT),
                text(title).size(theme::sz(19.0)).color(theme::TEXT),
            ]
            .align_y(iced::Alignment::Center)
            .spacing(8),
            text(epigraph).size(theme::sz(12.0)).color(theme::DIM),
            Space::new().height(Length::Fixed(12.0)),
            hline(),
            Space::new().height(Length::Fixed(18.0)),
            content.into(),
        ]
        .padding(24),
    )
    .max_width(1180.0)
    .center_x(Fill)
    .into()
}
