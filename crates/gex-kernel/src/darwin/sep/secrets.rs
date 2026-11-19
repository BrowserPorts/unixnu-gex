//! The web device's Secure Enclave secrets.
//!
//! A SEP's keys all descend from its UID, a 256-bit AES key fused into the
//! chip that only the SEP's AES engine can use: the sepOS asks the engine to
//! encrypt with it and never sees it. The web device has no fuses, so its
//! UID is a file of its directory ([`super::super::webdevice::files::SEP_UID`],
//! made with the device by `gexc darwin-web-device init`, or added to one
//! made before by `gexc darwin-web-device sep <dir>`), which only the SEP
//! core's AES engine reads ([`SepUid::load`]). It is not the AP's UID
//! ([`super::super::webdevice::files::UID`]): the two engines have their own
//! fuses.
//!
//! The bytes are never printed (`Debug` names the type only), never copied
//! out of the engine's model, and overwritten when the value is dropped.

use super::super::webdevice::files;
use std::path::Path;

/// The length of a UID: an AES-256 key.
pub const UID_LEN: usize = 32;

/// The SEP's UID. Only the AES engine's UID key slot holds it.
pub struct SepUid([u8; UID_LEN]);

impl std::fmt::Debug for SepUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SepUid(..)")
    }
}

impl Drop for SepUid {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
        std::hint::black_box(&mut self.0);
    }
}

/// Why a UID is not there.
#[derive(Debug, PartialEq, Eq)]
pub enum Missing {
    /// The web device's directory has no [`files::SEP_UID`]: a device made
    /// before the SEP's secrets were (`gexc darwin-web-device sep <dir>`).
    NoFile(String),
    /// The file is not [`UID_LEN`] bytes: not one this tool made.
    Length(String, usize),
    /// Reading it failed.
    Io(String, String),
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Missing::NoFile(p) => write!(f, "the web device has no SEP UID ({p}): add one with `gexc darwin-web-device sep <dir>`"),
            Missing::Length(p, n) => write!(f, "the web device's SEP UID {p} is {n} bytes, not {UID_LEN}"),
            Missing::Io(p, e) => write!(f, "reading the web device's SEP UID {p}: {e}"),
        }
    }
}

impl SepUid {
    /// The UID of the web device whose directory is `dir`.
    pub fn load(dir: &Path) -> Result<SepUid, Missing> {
        let path = dir.join(files::SEP_UID);
        let shown = path.display().to_string();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Missing::NoFile(shown)),
            Err(e) => return Err(Missing::Io(shown, e.to_string())),
        };
        let uid: [u8; UID_LEN] = match bytes.as_slice().try_into() {
            Ok(u) => u,
            Err(_) => return Err(Missing::Length(shown, bytes.len())),
        };
        Ok(SepUid(uid))
    }

    /// The key as the AES engine's UID slot takes it. Only the engine's
    /// model calls this.
    pub(super) fn key(&self) -> &[u8; UID_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gex-sep-uid-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_uid_is_read_and_never_shown() {
        let d = dir("ok");
        std::fs::write(d.join(files::SEP_UID), [0x5a; UID_LEN]).unwrap();
        let u = SepUid::load(&d).unwrap();
        assert_eq!(u.key(), &[0x5a; UID_LEN]);
        assert_eq!(format!("{u:?}"), "SepUid(..)");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_aps_uid_is_not_the_seps() {
        let d = dir("ap");
        std::fs::write(d.join(files::UID), [1; UID_LEN]).unwrap();
        match SepUid::load(&d) {
            Err(Missing::NoFile(p)) => assert!(p.ends_with(files::SEP_UID)),
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_wrong_length_is_refused() {
        let d = dir("len");
        std::fs::write(d.join(files::SEP_UID), [1; 16]).unwrap();
        assert_eq!(SepUid::load(&d).unwrap_err(), Missing::Length(d.join(files::SEP_UID).display().to_string(), 16));
        let _ = std::fs::remove_dir_all(&d);
    }
}
