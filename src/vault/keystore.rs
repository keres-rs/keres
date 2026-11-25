//! Vault key management: a slot table of password-derived KEKs wrapping one
//! random master key.
//!
//! The master key is generated once at `init` and never changes; changing a
//! password only re-wraps that slot. Adding a keyslot wraps the same master
//! key under an independent KEK, so several passphrases can open one vault and
//! individual slots can be revoked. The unwrapped master key lives exclusively
//! in zeroizing memory and is handed out by reference.
//!
//! The on-disk config is a small JSON document (not a container): it must be
//! readable before any key exists — the bootstrap of the whole hierarchy.
//! Version 2 configs (one implicit slot) are still read and are upgraded to
//! version 3 the next time a key operation rewrites the config.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::kdf::KdfParams;

/// Current config schema version.
pub(crate) const CONFIG_VERSION: u32 = 3;

/// Legacy config schema: one password-derived wrapping and no slot table.
const LEGACY_CONFIG_VERSION: u32 = 2;

/// AAD for the legacy config wrapping.
const LEGACY_CONFIG_AAD: &[u8] = b"keres-vault-config-v2";

/// Prefix for the per-slot AAD; the slot id is appended. Binding the id
/// prevents a wrapped key from being moved between slots undetected.
const SLOT_AAD_PREFIX: &str = "keres-vault-config-v3/";

/// Reported id for the single implicit slot in a legacy config.
pub(crate) const LEGACY_SLOT_ID: &str = "legacy";

/// Public description of one keyslot. Contains no secret material: slot ids
/// are stored in plaintext in `vault.config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyslotInfo {
    /// Stable random slot id, used to revoke the slot later.
    pub id: String,
}

/// Legacy v2 config: KDF parameters plus one wrapped master key.
#[derive(Serialize, Deserialize)]
pub(crate) struct LegacyConfig {
    version: u32,
    kdf: KdfParams,
    salt: Vec<u8>,
    wrapped_master_key: Vec<u8>,
}

/// One independent passphrase wrapping the master key.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeySlot {
    pub id: String,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_master_key: Vec<u8>,
}

/// Current v3 config: a non-empty table of independent keyslots.
#[derive(Serialize, Deserialize)]
pub(crate) struct SlotConfig {
    version: u32,
    slots: Vec<KeySlot>,
}

/// On-disk vault config, tagged by its schema version.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum VaultConfig {
    /// 0.5.x single-password bootstrap.
    Legacy(LegacyConfig),
    /// Current slot table.
    Slots(SlotConfig),
}

impl VaultConfig {
    /// Parses and validates a config document.
    ///
    /// Version 2 is accepted for upgrades; every newer unknown version fails
    /// with [`Error::UnsupportedVersion`]. Individual slots are validated
    /// before any key derivation so a hostile config cannot request absurd
    /// KDF work or huge allocations.
    pub(crate) fn parse(json: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| Error::InvalidVault)?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(Error::InvalidVault)?;
        let version = u32::try_from(version).map_err(|_| Error::InvalidVault)?;

        match version {
            LEGACY_CONFIG_VERSION => {
                let config: LegacyConfig =
                    serde_json::from_value(value).map_err(|_| Error::InvalidVault)?;
                validate_legacy(&config)?;
                Ok(Self::Legacy(config))
            }
            CONFIG_VERSION => {
                let config: SlotConfig =
                    serde_json::from_value(value).map_err(|_| Error::InvalidVault)?;
                if config.slots.is_empty() {
                    return Err(Error::InvalidVault);
                }
                let mut ids = HashSet::with_capacity(config.slots.len());
                for slot in &config.slots {
                    slot.validate()?;
                    if !ids.insert(slot.id.as_str()) {
                        return Err(Error::InvalidVault);
                    }
                }
                Ok(Self::Slots(config))
            }
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    /// Builds a new single-slot config around `master`.
    pub(crate) fn new(master: &Key, password: &str) -> Result<Self> {
        Ok(Self::Slots(SlotConfig {
            version: CONFIG_VERSION,
            slots: vec![KeySlot::wrap(master, password)?],
        }))
    }

    /// Slot descriptions in on-disk order.
    pub(crate) fn slot_ids(&self) -> Vec<KeyslotInfo> {
        match self {
            Self::Legacy(_) => vec![KeyslotInfo {
                id: LEGACY_SLOT_ID.to_string(),
            }],
            Self::Slots(config) => config
                .slots
                .iter()
                .map(|slot| KeyslotInfo {
                    id: slot.id.clone(),
                })
                .collect(),
        }
    }

    /// Finds a slot by id.
    pub(crate) fn slot_index(&self, id: &str) -> Option<usize> {
        match self {
            Self::Legacy(_) => (id == LEGACY_SLOT_ID).then_some(0),
            Self::Slots(config) => config.slots.iter().position(|slot| slot.id == id),
        }
    }

    /// Unwraps the master key with `password`, returning the slot that
    /// matched.
    ///
    /// Authentication failure reports [`Error::Authentication`] without
    /// distinguishing a wrong password from a tampered wrapping. A malformed
    /// slot is [`Error::InvalidVault`] and aborts immediately: that is
    /// tampering, not a wrong passphrase.
    pub(crate) fn unlock(&self, password: &str) -> Result<(Key, usize)> {
        match self {
            Self::Legacy(config) => Ok((open_legacy(config, password)?, 0)),
            Self::Slots(config) => {
                for (index, slot) in config.slots.iter().enumerate() {
                    match slot.open(password) {
                        Ok(master) => return Ok((master, index)),
                        Err(Error::Authentication) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Err(Error::Authentication)
            }
        }
    }

    /// Unwraps the master key, discarding the matching slot index.
    pub(crate) fn unwrap_master_key(&self, password: &str) -> Result<Key> {
        self.unlock(password).map(|(master, _)| master)
    }

    /// Re-wraps the slot at `index` under `new_password`.
    ///
    /// A legacy config is rewritten as a v3 config with a fresh slot id; a v3
    /// slot keeps its id so revocation targets stay stable.
    pub(crate) fn rewrap_slot(
        &self,
        index: usize,
        master: &Key,
        new_password: &str,
    ) -> Result<Self> {
        match self {
            Self::Legacy(_) => {
                if index != 0 {
                    return Err(Error::InvalidVault);
                }
                Self::new(master, new_password)
            }
            Self::Slots(config) => {
                let id = config
                    .slots
                    .get(index)
                    .ok_or(Error::InvalidVault)?
                    .id
                    .clone();
                let mut slots = config.slots.clone();
                slots[index] = KeySlot::wrap_with_id(master, new_password, id)?;
                Ok(Self::Slots(SlotConfig {
                    version: CONFIG_VERSION,
                    slots,
                }))
            }
        }
    }

    /// Adds a slot wrapping `master` under `new_password`.
    ///
    /// `existing_password` must be the passphrase that unlocked a slot; a
    /// legacy config is converted to v3 by re-wrapping its implicit slot under
    /// that same passphrase first, so the upgrade does not change any
    /// credential.
    pub(crate) fn add_slot(
        &self,
        master: &Key,
        existing_password: &str,
        new_password: &str,
    ) -> Result<(Self, KeyslotInfo)> {
        let new_slot = KeySlot::wrap(master, new_password)?;
        let info = KeyslotInfo {
            id: new_slot.id.clone(),
        };

        let slots = match self {
            Self::Legacy(_) => vec![KeySlot::wrap(master, existing_password)?, new_slot],
            Self::Slots(config) => {
                let mut slots = config.slots.clone();
                slots.push(new_slot);
                slots
            }
        };

        Ok((
            Self::Slots(SlotConfig {
                version: CONFIG_VERSION,
                slots,
            }),
            info,
        ))
    }

    /// Removes the slot at `index`, refusing to delete the only remaining
    /// credential.
    pub(crate) fn remove_slot(&self, index: usize) -> Result<Self> {
        match self {
            Self::Legacy(_) => Err(Error::Operation(
                "the legacy config has a single implicit keyslot; add a keyslot first".into(),
            )),
            Self::Slots(config) => {
                if index >= config.slots.len() {
                    return Err(Error::InvalidVault);
                }
                if config.slots.len() == 1 {
                    return Err(Error::Operation(
                        "refusing to remove the only keyslot".into(),
                    ));
                }
                let mut slots = config.slots.clone();
                slots.remove(index);
                Ok(Self::Slots(SlotConfig {
                    version: CONFIG_VERSION,
                    slots,
                }))
            }
        }
    }
}

impl KeySlot {
    /// Wraps `master` under a fresh KEK with a new random id.
    fn wrap(master: &Key, password: &str) -> Result<Self> {
        Self::wrap_with_id(master, password, new_slot_id())
    }

    /// Wraps `master` under a fresh KEK, reusing `id` (for password changes).
    fn wrap_with_id(master: &Key, password: &str, id: String) -> Result<Self> {
        let mut salt = [0u8; crypto::SALT_LEN];
        crypto::fill_random(&mut salt);
        let params = KdfParams::new();
        let kek = crypto::derive_key(password.as_bytes(), &salt, params)?;

        let nonce = crypto::random_nonce();
        // Zeroizing: the buffer holds the raw master key until sealed in
        // place, and must be scrubbed when it goes out of scope.
        let mut buf = Zeroizing::new(master.expose().to_vec());
        crypto::seal_in_place(&nonce, &mut buf, &kek, slot_aad(&id).as_slice())?;

        Ok(Self {
            id,
            kdf: params,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            wrapped_master_key: buf.to_vec(),
        })
    }

    fn aad(&self) -> Vec<u8> {
        slot_aad(&self.id)
    }

    /// Validates structural fields before any expensive work.
    fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.salt.len() < 8
            || self.nonce.len() != crypto::NONCE_LEN
            || self.wrapped_master_key.len() != crypto::KEY_LEN + crypto::TAG_LEN
        {
            return Err(Error::InvalidVault);
        }
        self.kdf.validate()
    }

    /// Unwraps the master key with a password-derived KEK.
    fn open(&self, password: &str) -> Result<Key> {
        self.validate()?;
        let kek = crypto::derive_key(password.as_bytes(), &self.salt, self.kdf)?;
        let nonce = nonce_from_slice(&self.nonce)?;
        let plain = crypto::open(&self.wrapped_master_key, &nonce, &kek, &self.aad())?;
        key_from_plaintext(&plain)
    }
}

fn slot_aad(id: &str) -> Vec<u8> {
    format!("{SLOT_AAD_PREFIX}{id}").into_bytes()
}

fn new_slot_id() -> String {
    let mut raw = [0u8; 8];
    crypto::fill_random(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_legacy(config: &LegacyConfig) -> Result<()> {
    if config.version != LEGACY_CONFIG_VERSION
        || config.salt.len() < 8
        || config.wrapped_master_key.len() != crypto::KEY_LEN + crypto::TAG_LEN
    {
        return Err(Error::InvalidVault);
    }
    config.kdf.validate()
}

/// Opens a legacy single-slot config.
///
/// The fixed nonce is safe here for the same reason it was in 0.5.x: the KEK
/// is unique per vault (fresh random salt) and this exact (key, nonce) pair
/// encrypts exactly one short message ever.
fn open_legacy(config: &LegacyConfig, password: &str) -> Result<Key> {
    validate_legacy(config)?;
    let kek = crypto::derive_key(password.as_bytes(), &config.salt, config.kdf)?;
    let nonce = legacy_nonce();
    let plain = crypto::open(&config.wrapped_master_key, &nonce, &kek, LEGACY_CONFIG_AAD)?;
    key_from_plaintext(&plain)
}

fn legacy_nonce() -> [u8; crypto::NONCE_LEN] {
    let mut nonce = [0xFFu8; crypto::NONCE_LEN];
    nonce[0] = 0x01;
    nonce
}

fn nonce_from_slice(bytes: &[u8]) -> Result<[u8; crypto::NONCE_LEN]> {
    bytes.try_into().map_err(|_| Error::InvalidVault)
}

fn key_from_plaintext(plain: &[u8]) -> Result<Key> {
    if plain.len() != crypto::KEY_LEN {
        return Err(Error::InvalidVault);
    }
    let mut bytes = [0u8; crypto::KEY_LEN];
    bytes.copy_from_slice(plain);
    Ok(Key::from_bytes(bytes))
}

/// In-memory unlocked state of a vault.
#[derive(Default)]
pub(crate) struct KeyStore {
    master_key: Option<Key>,
}

impl KeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub(crate) fn master_key(&self) -> Result<&Key> {
        self.master_key.as_ref().ok_or(Error::VaultLocked)
    }

    /// Creates a fresh master key wrapped under `password`.
    pub(crate) fn init(&mut self, password: &str) -> Result<VaultConfig> {
        let master = Key::generate();
        let config = VaultConfig::new(&master, password)?;
        self.master_key = Some(master);
        Ok(config)
    }

    /// Unlocks using any slot in the parsed config.
    pub(crate) fn unlock(&mut self, password: &str, config: &VaultConfig) -> Result<()> {
        if self.is_unlocked() {
            return Err(Error::VaultUnlocked);
        }
        let master = config.unwrap_master_key(password)?;
        self.master_key = Some(master);
        Ok(())
    }

    pub(crate) fn lock(&mut self) {
        self.master_key = None; // Key zeroizes on drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a legacy (0.5.x) config exactly as the old writer did.
    fn legacy_config(master: &Key, password: &str) -> String {
        let mut salt = [0u8; 32];
        crypto::fill_random(&mut salt);
        let params = KdfParams::new();
        let kek = crypto::derive_key(password.as_bytes(), &salt, params).unwrap();
        let mut buf = Zeroizing::new(master.expose().to_vec());
        crypto::seal_in_place(&legacy_nonce(), &mut buf, &kek, LEGACY_CONFIG_AAD).unwrap();

        serde_json::to_string_pretty(&LegacyConfig {
            version: LEGACY_CONFIG_VERSION,
            kdf: params,
            salt: salt.to_vec(),
            wrapped_master_key: buf.to_vec(),
        })
        .unwrap()
    }

    #[test]
    fn v3_roundtrip_and_slot_listing() {
        let master = Key::generate();
        let config = VaultConfig::new(&master, "pw").unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();

        let parsed = VaultConfig::parse(&json).unwrap();
        let (unwrapped, index) = parsed.unlock("pw").unwrap();
        assert_eq!(index, 0);
        assert_eq!(unwrapped.expose(), master.expose());

        let ids = parsed.slot_ids();
        assert_eq!(ids.len(), 1);
        assert_eq!(parsed.slot_index(&ids[0].id), Some(0));
        assert_eq!(parsed.slot_index("nope"), None);
    }

    #[test]
    fn legacy_config_unlocks_and_upgrades_on_add() {
        let master = Key::generate();
        let legacy = VaultConfig::parse(&legacy_config(&master, "old")).unwrap();
        assert_eq!(
            legacy.slot_ids(),
            vec![KeyslotInfo {
                id: LEGACY_SLOT_ID.to_string()
            }]
        );
        assert_eq!(
            legacy.unwrap_master_key("old").unwrap().expose(),
            master.expose()
        );

        let (upgraded, info) = legacy.add_slot(&master, "old", "new").unwrap();
        assert!(matches!(upgraded, VaultConfig::Slots(_)));
        assert_eq!(upgraded.slot_ids().len(), 2);
        assert_eq!(
            upgraded.unwrap_master_key("old").unwrap().expose(),
            master.expose()
        );
        assert_eq!(
            upgraded.unwrap_master_key("new").unwrap().expose(),
            master.expose()
        );
        assert!(upgraded.slot_index(&info.id).is_some());
    }

    #[test]
    fn rewrapping_one_slot_keeps_the_others() {
        let master = Key::generate();
        let config = VaultConfig::new(&master, "first").unwrap();
        let (config, _) = config.add_slot(&master, "first", "second").unwrap();

        let (_, index) = config.unlock("first").unwrap();
        let changed = config.rewrap_slot(index, &master, "first-new").unwrap();

        assert!(matches!(
            changed.unwrap_master_key("first"),
            Err(Error::Authentication)
        ));
        assert_eq!(
            changed.unwrap_master_key("first-new").unwrap().expose(),
            master.expose()
        );
        assert_eq!(
            changed.unwrap_master_key("second").unwrap().expose(),
            master.expose()
        );
    }

    #[test]
    fn removing_the_only_slot_is_refused() {
        let master = Key::generate();
        let config = VaultConfig::new(&master, "pw").unwrap();
        assert!(matches!(config.remove_slot(0), Err(Error::Operation(_))));
    }

    #[test]
    fn slot_identity_is_bound_into_the_aad() {
        let master = Key::generate();
        let config = VaultConfig::new(&master, "pw").unwrap();
        let (config, _) = config.add_slot(&master, "pw", "other").unwrap();

        let VaultConfig::Slots(mut slots) = config else {
            panic!("expected v3 config");
        };
        // Swap the wrapped material but keep each slot's id. The AAD binds
        // the id, so neither slot opens after the transplant.
        let first = slots.slots[0].clone();
        let second = slots.slots[1].clone();
        slots.slots[0].wrapped_master_key = second.wrapped_master_key;
        slots.slots[0].nonce = second.nonce;
        slots.slots[0].salt = second.salt;
        slots.slots[1].wrapped_master_key = first.wrapped_master_key;
        slots.slots[1].nonce = first.nonce;
        slots.slots[1].salt = first.salt;

        let tampered = VaultConfig::Slots(slots);
        assert!(matches!(
            tampered.unwrap_master_key("pw"),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn malformed_and_future_configs_are_rejected() {
        assert!(matches!(
            VaultConfig::parse("{\"version\":4,\"slots\":[]}"),
            Err(Error::UnsupportedVersion(4))
        ));
        assert!(matches!(
            VaultConfig::parse("{\"version\":3,\"slots\":[]}"),
            Err(Error::InvalidVault)
        ));
        assert!(matches!(
            VaultConfig::parse("not json"),
            Err(Error::InvalidVault)
        ));
    }
}
