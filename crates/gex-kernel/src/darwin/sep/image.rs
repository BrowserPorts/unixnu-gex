//! The sepOS image the owner supplies.
//!
//! The sepOS (`sep-firmware.<board>.RELEASE.im4p`, type `sepi`) is
//! encrypted under the SEP's own GID key, which only the SEP ROM holds: the
//! AP never decrypts it (AppleSEPManager copies the IMG4 the user client
//! gives it into the SEP's firmware region and hands it to the ROM). The web
//! device has no ROM and no GID, so it runs a sepOS whose payload the owner
//! decrypted on a device (`GEX_DARWIN_SEPOS`, the decrypted payload as a
//! file: not the IM4P).
//!
//! What this checks is only what shows a file is not a decrypted sepOS: it
//! is not empty, it is not an IM4P (a file that still carries its
//! keybags), and its bytes are not the uniform noise of ciphertext (an
//! AES-CBC payload, or one decrypted with the wrong key, has about eight
//! bits of entropy a byte; code and data have fewer). The layout inside
//! (its header, its modules) is for the SEP core to read from the image.

use std::path::{Path, PathBuf};

/// A decrypted sepOS payload.
#[derive(Debug)]
pub struct SepOsImage {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// Why a file is not a decrypted sepOS.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageError {
    Io(String),
    Empty,
    /// The file is an IM4P (DER `IM4P` with its keybags): the payload is
    /// still encrypted, or must be extracted from it.
    Im4p,
    /// Eight bits of entropy a byte: ciphertext, or a wrong key's output.
    Noise(String),
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::Io(e) => f.write_str(e),
            ImageError::Empty => f.write_str("the file is empty"),
            ImageError::Im4p => f.write_str("the file is an IM4P, not its decrypted payload (extract it with the SEP GID key's IV and key: `ipsw img4 im4p extract --iv <iv> --key <key> -o <out> <im4p>`)"),
            ImageError::Noise(e) => write!(f, "the file looks encrypted ({e} bits of entropy a byte): the SEP GID key did not decrypt it"),
        }
    }
}

/// Shannon entropy of `b`, in bits a byte.
pub fn entropy(b: &[u8]) -> f64 {
    let mut count = [0usize; 256];
    for &c in b {
        count[c as usize] += 1;
    }
    let n = b.len() as f64;
    count.iter().filter(|&&c| c != 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Whether `b` begins with a DER SEQUENCE whose first element is the IA5String `IM4P`.
fn is_im4p(b: &[u8]) -> bool {
    if b.first() != Some(&0x30) {
        return false;
    }
    let skip = match b.get(1) {
        Some(&l) if l & 0x80 != 0 => 2 + (l & 0x7f) as usize,
        Some(_) => 2,
        None => return false,
    };
    b.get(skip..skip + 6) == Some(&[0x16, 0x04, b'I', b'M', b'4', b'P'])
}

/// The most entropy a decrypted image's bytes may have, in bits a byte:
/// ciphertext of a megabyte or more has 7.999.
const NOISE: f64 = 7.9;

impl SepOsImage {
    /// A payload's bytes checked as above.
    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<SepOsImage, ImageError> {
        if bytes.is_empty() {
            return Err(ImageError::Empty);
        }
        if is_im4p(&bytes) {
            return Err(ImageError::Im4p);
        }
        // Entropy is only meaningful over enough bytes to fill the
        // alphabet: a short file is not judged by it.
        if bytes.len() >= 64 * 1024 {
            let e = entropy(&bytes);
            if e >= NOISE {
                return Err(ImageError::Noise(format!("{e:.3}")));
            }
        }
        Ok(SepOsImage { path, bytes })
    }

    pub fn load(path: &Path) -> Result<SepOsImage, ImageError> {
        let bytes = std::fs::read(path).map_err(|e| ImageError::Io(format!("reading {}: {e}", path.display())))?;
        SepOsImage::from_bytes(path.to_path_buf(), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift noise: uniform bytes, as ciphertext is.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..n).map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        }).collect()
    }

    #[test]
    fn noise_is_refused_as_ciphertext() {
        let e = SepOsImage::from_bytes("x".into(), noise(1 << 20)).unwrap_err();
        assert!(matches!(e, ImageError::Noise(_)), "{e:?}");
    }

    #[test]
    fn structured_bytes_pass() {
        let mut b = Vec::new();
        for i in 0..(1 << 18) {
            b.extend_from_slice(&(i as u32).to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
        }
        assert!(entropy(&b) < NOISE);
        assert!(SepOsImage::from_bytes("x".into(), b).is_ok());
    }

    #[test]
    fn an_im4p_and_an_empty_file_are_refused() {
        let mut im4p = vec![0x30, 0x83, 0x15, 0x69, 0x09, 0x16, 0x04, b'I', b'M', b'4', b'P'];
        im4p.resize(100, 0);
        assert_eq!(SepOsImage::from_bytes("x".into(), im4p).unwrap_err(), ImageError::Im4p);
        assert_eq!(SepOsImage::from_bytes("x".into(), Vec::new()).unwrap_err(), ImageError::Empty);
    }

    #[test]
    fn a_missing_file_is_reported_by_name() {
        let e = SepOsImage::load(Path::new("/no/such/sepos.bin")).unwrap_err();
        assert!(e.to_string().contains("/no/such/sepos.bin"), "{e}");
    }
}
