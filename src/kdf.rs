use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Argon2id parameters.
///
/// Parameters are stored inside every encrypted container so that defaults can
/// evolve in the future without breaking older files. When parsing parameters
/// from untrusted input they are validated against the bounds documented on
/// each field to prevent denial-of-service via absurd values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB (Argon2 `m`). Default 65536 (64 MiB).
    /// Accepted range when reading untrusted input: 8 MiB ..= 4 GiB.
    pub m_cost_kib: u32,
    /// Time cost — number of passes (Argon2 `t`). Default 4.
    /// Accepted range: 1 ..= 64.
    pub t_cost: u32,
    /// Degree of parallelism (Argon2 `p`). Default 4.
    /// Accepted range: 1 ..= 16.
    pub p_cost: u32,
}

impl KdfParams {
    /// Library defaults: Argon2id with 64 MiB memory, 4 passes, parallelism 4
    /// (matches the krypton CLI ≥ 0.2).
    pub const fn new() -> Self {
        Self {
            m_cost_kib: 65_536,
            t_cost: 4,
            p_cost: 4,
        }
    }

    pub(crate) const SERIALIZED_LEN: usize = 12;

    pub(crate) fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        buf[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        buf[8..12].copy_from_slice(&self.p_cost.to_le_bytes());
    }

    /// Parses and validates parameters from a 12-byte little-endian encoding.
    pub fn read_from(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SERIALIZED_LEN {
            return Err(Error::InvalidHeader);
        }
        let params = Self {
            m_cost_kib: u32::from_le_bytes(buf[0..4].try_into().map_err(|_| Error::InvalidHeader)?),
            t_cost: u32::from_le_bytes(buf[4..8].try_into().map_err(|_| Error::InvalidHeader)?),
            p_cost: u32::from_le_bytes(buf[8..12].try_into().map_err(|_| Error::InvalidHeader)?),
        };
        params.validate()?;
        Ok(params)
    }

    /// Validates the parameters against safety bounds.
    ///
    /// The upper bounds exist so that a hostile config file cannot make the
    /// process attempt an absurd allocation; the lower bound rejects settings
    /// so weak that no meaningful protection is provided.
    pub fn validate(&self) -> Result<()> {
        const MIN_M_KIB: u32 = 8 * 1024;
        const MAX_M_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
        const MIN_T: u32 = 1;
        const MAX_T: u32 = 64;
        const MIN_P: u32 = 1;
        const MAX_P: u32 = 16;

        if !(MIN_M_KIB..=MAX_M_KIB).contains(&self.m_cost_kib) {
            return Err(Error::InvalidKdfParams);
        }
        if !(MIN_T..=MAX_T).contains(&self.t_cost) {
            return Err(Error::InvalidKdfParams);
        }
        if !(MIN_P..=MAX_P).contains(&self.p_cost) {
            return Err(Error::InvalidKdfParams);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(KdfParams::new().validate().is_ok());
    }

    #[test]
    fn roundtrip_serialization() {
        let params = KdfParams {
            m_cost_kib: 131_072,
            t_cost: 3,
            p_cost: 2,
        };
        let mut buf = [0u8; KdfParams::SERIALIZED_LEN];
        params.write_to(&mut buf);
        assert_eq!(KdfParams::read_from(&buf).unwrap(), params);
    }

    #[test]
    fn rejects_out_of_bounds() {
        assert!(KdfParams {
            m_cost_kib: 1,
            ..KdfParams::new()
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_cost_kib: u32::MAX,
            ..KdfParams::new()
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            t_cost: 0,
            ..KdfParams::new()
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            t_cost: 65,
            ..KdfParams::new()
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            p_cost: 17,
            ..KdfParams::new()
        }
        .validate()
        .is_err());
    }
}
