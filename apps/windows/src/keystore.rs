//! T-10 — identity and pairing persistence, PROTOCOL.md §3.
//!
//! Identity seed is DPAPI-sealed (`CryptProtectData`, per-user scope) at
//! `%LOCALAPPDATA%\AirClip\identity.bin`; pairings are DPAPI-sealed JSON beside it.
//! CLAUDE.md forbids unprotected key files on Windows.

use std::fs;
use std::path::{Path, PathBuf};

use airclip_core::crypto::IdentityKeypair;
use airclip_core::pairing::PairingRecord;
use anyhow::{Context, Result};

const IDENTITY_FILE: &str = "identity.bin";
const PAIRINGS_FILE: &str = "pairings.bin";

// `at`/`dir`/`remove_pairing` are exercised by tests and will back the tray's
// "Forget device" item (T-12); keeping them avoids re-deriving the same paths there.
#[allow(dead_code)]
const _: () = ();

pub struct Keystore {
    dir: PathBuf,
}

#[allow(dead_code)]
impl Keystore {
    /// Open (creating if needed) `%LOCALAPPDATA%\AirClip`.
    pub fn open() -> Result<Self> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(dirs_fallback)
            .context("cannot determine LOCALAPPDATA")?;
        let dir = base.join("AirClip");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// Test/simulation constructor.
    pub fn at(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Load the device identity, generating and sealing one on first run.
    pub fn load_or_create_identity(&self) -> Result<IdentityKeypair> {
        let path = self.dir.join(IDENTITY_FILE);
        if path.exists() {
            let sealed = fs::read(&path)?;
            let seed = unseal(&sealed).context("unsealing identity (wrong Windows user?)")?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity seed must be 32 bytes"))?;
            return Ok(IdentityKeypair::from_seed(seed));
        }

        let identity = IdentityKeypair::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
        let seed = identity.secret_bytes();
        let sealed = seal(seed.as_ref())?;
        write_atomic(&path, &sealed)?;
        tracing::info!(device_id = %identity.device_id().hex(), "generated new device identity");
        Ok(identity)
    }

    pub fn load_pairings(&self) -> Result<Vec<PairingRecord>> {
        let path = self.dir.join(PAIRINGS_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let sealed = fs::read(&path)?;
        let json = unseal(&sealed).context("unsealing pairings")?;
        Ok(serde_json::from_slice(&json)?)
    }

    pub fn save_pairings(&self, records: &[PairingRecord]) -> Result<()> {
        let json = serde_json::to_vec(records)?;
        let sealed = seal(&json)?;
        write_atomic(&self.dir.join(PAIRINGS_FILE), &sealed)
    }

    /// Add or replace a pairing (keyed by device id) and persist.
    pub fn upsert_pairing(&self, record: PairingRecord) -> Result<Vec<PairingRecord>> {
        let mut all = self.load_pairings().unwrap_or_default();
        all.retain(|r| r.device_id != record.device_id);
        all.push(record);
        self.save_pairings(&all)?;
        Ok(all)
    }

    pub fn remove_pairing(&self, device_id_hex: &str) -> Result<Vec<PairingRecord>> {
        let mut all = self.load_pairings().unwrap_or_default();
        all.retain(|r| r.device_id != device_id_hex);
        self.save_pairings(&all)?;
        Ok(all)
    }
}

fn dirs_fallback() -> Option<PathBuf> {
    // Non-Windows dev/CI hosts have no LOCALAPPDATA.
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"))
}

/// Write via temp + rename so a crash mid-write cannot truncate a key file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    win_dpapi::protect(plain)
}

#[cfg(windows)]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    win_dpapi::unprotect(sealed)
}

// Non-Windows builds exist only so `airclip-core` development and CI can compile the
// workspace on Linux. Storing key material unprotected is never acceptable on the real
// target, hence the loud warning and the cfg gate.
#[cfg(not(windows))]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    tracing::warn!("DPAPI unavailable on this platform — key material is NOT protected at rest");
    Ok(plain.to_vec())
}

#[cfg(not(windows))]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    Ok(sealed.to_vec())
}

#[cfg(windows)]
mod win_dpapi {
    use anyhow::{bail, Result};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// Copy a DPAPI output blob out and release the CryptoAPI allocation.
    ///
    /// # Safety
    /// `blob` must be a blob CryptoAPI filled in and still owns.
    unsafe fn take_blob(blob: &mut CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let out = if blob.pbData.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec()
        };
        if !blob.pbData.is_null() {
            let _ = LocalFree(Some(HLOCAL(blob.pbData as *mut _)));
            blob.pbData = std::ptr::null_mut();
        }
        out
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: input points at `plain` for the duration of the call; output is
        // owned by CryptoAPI until take_blob frees it.
        unsafe {
            CryptProtectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )?;
            let sealed = take_blob(&mut output);
            if sealed.is_empty() {
                bail!("CryptProtectData returned an empty blob");
            }
            Ok(sealed)
        }
    }

    pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: sealed.len() as u32,
            pbData: sealed.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: as above.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )?;
            Ok(take_blob(&mut output))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airclip-keystore-test-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn identity_is_stable_across_reopen() {
        let dir = temp_dir("identity");
        let ks = Keystore::at(&dir).unwrap();
        let a = ks.load_or_create_identity().unwrap();
        let b = ks.load_or_create_identity().unwrap();
        assert_eq!(a.public_bytes(), b.public_bytes(), "identity must persist");
        assert_eq!(a.device_id(), b.device_id());

        // A fresh handle to the same directory sees the same identity.
        let ks2 = Keystore::at(&dir).unwrap();
        assert_eq!(
            ks2.load_or_create_identity().unwrap().device_id(),
            a.device_id()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn identity_file_is_not_the_raw_seed() {
        // Guards the CLAUDE.md rule: the secret must never sit unprotected on disk.
        let dir = temp_dir("sealed");
        let ks = Keystore::at(&dir).unwrap();
        let id = ks.load_or_create_identity().unwrap();
        let raw = fs::read(dir.join(IDENTITY_FILE)).unwrap();

        let seed = id.secret_bytes();
        assert!(raw.len() > 32, "DPAPI blob should be larger than the seed");
        assert!(
            !raw.windows(32).any(|w| w == seed.as_ref()),
            "raw seed found in the on-disk file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pairings_round_trip_and_upsert_is_keyed_by_device() {
        let dir = temp_dir("pairings");
        let ks = Keystore::at(&dir).unwrap();
        assert!(ks.load_pairings().unwrap().is_empty());

        let a = PairingRecord {
            device_id: "aa".repeat(16),
            public_key: "cGs".into(),
            display_name: "iPhone".into(),
            created_at_ms: 1,
            last_seen_ms: 1,
        };
        let all = ks.upsert_pairing(a.clone()).unwrap();
        assert_eq!(all.len(), 1);

        // Same device id with a new name replaces rather than duplicates.
        let mut renamed = a.clone();
        renamed.display_name = "Bernhard's iPhone".into();
        let all = ks.upsert_pairing(renamed).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].display_name, "Bernhard's iPhone");

        let mut other = a.clone();
        other.device_id = "bb".repeat(16);
        assert_eq!(ks.upsert_pairing(other).unwrap().len(), 2);

        let left = ks.remove_pairing(&a.device_id).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].device_id, "bb".repeat(16));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_pairings_file_is_not_an_error() {
        let dir = temp_dir("empty");
        let ks = Keystore::at(&dir).unwrap();
        assert!(ks.load_pairings().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
