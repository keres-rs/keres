use crate::passwords::PasswordsStore;
use crate::vaults::VaultSession;

#[derive(Default)]
pub struct AppState {
    pub vaults: VaultSession,
    pub passwords: PasswordsStore,
}
