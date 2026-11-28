mod app;
mod files;
mod passwords;
mod state;
mod theme;
mod ui;
mod util;
mod vaults;

use app::App;

// ------------------------------------------------------------------ entry ----

fn app_theme(_state: &App) -> iced::Theme {
    theme::app_theme()
}

fn app_title(_state: &App) -> String {
    "Keres Desktop — encrypted vaults and file containers".to_string()
}

fn main() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .subscription(App::subscription)
        .window_size(iced::Size::new(1180.0, 760.0))
        .centered()
        .default_font(theme::MONO)
        .theme(app_theme)
        .title(app_title)
        .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.txt");
        std::fs::write(&input, "secret data").unwrap();
        let cipher = dir.path().join("in.krf");
        let (written_cipher, _msg) = files::encrypt_file("pw", &input, Some(&cipher)).unwrap();
        assert_eq!(written_cipher, cipher);
        let out = files::default_decrypt_output(&cipher);
        let (orig_name, written, _msg) = files::decrypt_file("pw", &cipher, &out).unwrap();
        assert_eq!(orig_name, "in.txt");
        assert_eq!(written, out);
        assert_eq!(std::fs::read_to_string(&written).unwrap(), "secret data");
    }

    #[test]
    fn vault_dirs_and_passwords() {
        use crate::vaults::{KdfPreset, PaddingPreset};

        let base = tempfile::tempdir().unwrap();
        let mut vs = vaults::VaultSession {
            base_dir: base.path().join("vaults"),
            ..Default::default()
        };
        vaults::create_vault_with_options(
            &mut vs,
            "test",
            "pw",
            "pw",
            PaddingPreset::Adaptive,
            KdfPreset::Fast,
        )
        .unwrap();
        assert_eq!(vaults::list_vault_names(&vs), vec!["test"]);

        let status = vaults::status(&vs).unwrap();
        assert!(status.unlocked);
        assert_eq!(status.padding, "adaptive");
        assert_eq!(status.keyslots, 1);

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "x").unwrap();
        vs.open
            .as_mut()
            .unwrap()
            .vault
            .add(&f, Some("a.txt"))
            .unwrap();
        let entries = vaults::list_entries(&vs).unwrap();
        assert_eq!(entries.len(), 1);
        let report = vaults::verify_vault(&mut vs, "pw").unwrap();
        assert!(report.contains("OK"));

        // Add an independent keyslot, then revoke it with the original
        // passphrase.
        let before = vaults::keyslots(&vs).unwrap();
        vaults::add_keyslot(&mut vs, "pw", "laptop-pw").unwrap();
        let after = vaults::keyslots(&vs).unwrap();
        assert_eq!(after.len(), 2);
        let added = after
            .iter()
            .find(|id| !before.contains(id))
            .unwrap()
            .clone();
        vaults::remove_keyslot(&mut vs, &added, "pw").unwrap();
        assert_eq!(vaults::keyslots(&vs).unwrap().len(), 1);

        // A recovery kit can reset the passphrase after the vault is closed.
        let code = vaults::create_recovery_kit(&mut vs, "pw").unwrap();
        assert!(!code.is_empty());
        vaults::lock_vault(&mut vs).unwrap();
        vaults::recover_vault(&mut vs, "test", &code, "recovered").unwrap();
        vaults::unlock_vault(&mut vs, "test", "recovered").unwrap();

        vaults::change_vault_password(&mut vs, "recovered", "newpw").unwrap();
        vaults::lock_vault(&mut vs).unwrap();
        vaults::unlock_vault(&mut vs, "test", "newpw").unwrap();

        let pwdir = tempfile::tempdir().unwrap();
        let mut ps = passwords::PasswordsStore {
            path: pwdir.path().join("vault"),
            ..Default::default()
        };
        passwords::create(&mut ps, "pw").unwrap();
        passwords::save_entry(&mut ps, "github", "me", "hunter2").unwrap();
        let list = passwords::list_entries(&ps).unwrap();
        assert_eq!(list[0].2, "me");
    }

    #[test]
    fn password_generator_bounds() {
        let p = passwords::generate(12, true).unwrap();
        assert_eq!(p.len(), 12);
        let p2 = passwords::generate(32, false).unwrap();
        assert_eq!(p2.len(), 32);
    }
}
