//! The encrypted-file secret backend — the piece Go got for free from the
//! `99designs/keyring` library's file backend, ported by hand here because
//! the Rust `keyring` crate has no file backend at all.
//!
//! # Layout: one file per secret
//!
//! Each secret is its own file, named by hex-encoding the raw UTF-8 bytes
//! of its full namespaced key (e.g. `"module1/secret"`) with a `.secret`
//! extension. A single combined store file was the alternative, but it
//! would need its own internal locking/merge logic to make concurrent
//! writes to unrelated keys safe; one file per secret gets that for free
//! from the filesystem, and "temp file, then rename" maps directly onto
//! what an atomic write means for a single record. Hex rather than a hash
//! is used for the filename because it costs nothing extra (no hashing
//! dependency) and is trivially collision-free — the mapping only needs to
//! be safe, flat, and unique, never reversible or hidden.
//!
//! # Record format
//!
//! `nonce (24 bytes) || ciphertext+tag`. The cipher is XChaCha20-Poly1305;
//! the associated data is the *full namespaced key* being encrypted, so a
//! record copied or renamed onto a different key's filename fails to
//! decrypt instead of silently answering under the wrong name.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit as _, XChaCha20Poly1305, XNonce};
use rand::{Rng as _, RngCore as _};

use penguin_sdk::SecretError;

use crate::master_key::{MasterKey, ensure_master_key};

/// Bytes of random nonce prefixed to every record.
const NONCE_LEN: usize = 24;
/// Filename extension for a secret record.
const RECORD_EXTENSION: &str = "secret";
/// Filename the master key is stored under, inside the same directory as
/// the secret records it protects.
const MASTER_KEY_FILENAME: &str = "master.key";

/// The encrypted-file backend: one AEAD-encrypted record per secret, rooted
/// at a directory that also holds the master key.
pub struct FileBackend {
    dir: PathBuf,
    master_key: MasterKey,
}

impl FileBackend {
    /// Opens (creating if needed) the encrypted-file store rooted at `dir`.
    /// The master key lives at `dir/master.key`; `dir` itself must not be
    /// world-writable, enforced by [`ensure_master_key`].
    pub fn open(dir: PathBuf) -> Result<FileBackend, SecretError> {
        create_owner_only_dir(&dir)?;
        let master_key = ensure_master_key(&dir.join(MASTER_KEY_FILENAME))?;
        Ok(FileBackend { dir, master_key })
    }

    /// Reads and decrypts the record for `namespaced_key`. A missing file
    /// is [`SecretError::NotFound`]; a corrupt or foreign-key record is
    /// [`SecretError::Other`] — decryption failure is always a hard error,
    /// never a silent empty value.
    pub fn get(&self, namespaced_key: &str) -> Result<Vec<u8>, SecretError> {
        let path = self.record_path(namespaced_key);
        let record = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretError::NotFound);
            }
            Err(err) => {
                return Err(SecretError::Other(format!(
                    "failed to read secret file {}: {err}",
                    path.display()
                )));
            }
        };
        decrypt_record(&self.master_key, namespaced_key, &record)
    }

    /// Encrypts `value` under a fresh random nonce and atomically writes it
    /// as `namespaced_key`'s record, replacing any existing one.
    pub fn set(&self, namespaced_key: &str, value: &[u8]) -> Result<(), SecretError> {
        let record = encrypt_record(&self.master_key, namespaced_key, value)?;
        write_atomic(&self.record_path(namespaced_key), &record)
    }

    /// Deletes `namespaced_key`'s record. A missing key is
    /// [`SecretError::NotFound`], matching the Go store's `Delete`.
    pub fn delete(&self, namespaced_key: &str) -> Result<(), SecretError> {
        let path = self.record_path(namespaced_key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(SecretError::NotFound),
            Err(err) => Err(SecretError::Other(format!(
                "failed to delete secret file {}: {err}",
                path.display()
            ))),
        }
    }

    /// The on-disk path a given namespaced key's record lives at.
    fn record_path(&self, namespaced_key: &str) -> PathBuf {
        let name = hex_encode(namespaced_key.as_bytes());
        self.dir.join(format!("{name}.{RECORD_EXTENSION}"))
    }

    /// Test-only: exposes the record path so the crypto-binding tests below
    /// can read, corrupt, and cross-write raw record files directly.
    #[cfg(test)]
    fn test_record_path(&self, namespaced_key: &str) -> PathBuf {
        self.record_path(namespaced_key)
    }
}

/// Hex-encodes `bytes` into a lowercase string. Used for filenames rather
/// than a hash: the namespaced key is short, arbitrary, but trusted input,
/// so a reversible encoding is enough to make it filesystem-safe (no `/`
/// reinterpreted as a directory separator, no path traversal) without
/// pulling in a hashing dependency.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Builds the AEAD cipher for a given master key.
fn cipher_for(master_key: &MasterKey) -> Result<XChaCha20Poly1305, SecretError> {
    let key = <&Key>::try_from(master_key.as_bytes().as_slice()).map_err(|_| {
        SecretError::Other("master key has invalid length for XChaCha20Poly1305".to_string())
    })?;
    Ok(XChaCha20Poly1305::new(key))
}

/// Encrypts `plaintext` under a fresh random 24-byte nonce, with `aad_key`
/// (the full namespaced key) bound as associated data. Returns
/// `nonce || ciphertext+tag`.
fn encrypt_record(
    master_key: &MasterKey,
    aad_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = <&XNonce>::try_from(nonce_bytes.as_slice())
        .map_err(|_| SecretError::Other("generated nonce has unexpected length".to_string()))?;

    let payload = Payload {
        msg: plaintext,
        aad: aad_key.as_bytes(),
    };
    let ciphertext = cipher_for(master_key)?
        .encrypt(nonce, payload)
        .map_err(|_| SecretError::Other("failed to encrypt secret".to_string()))?;

    let mut record = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&ciphertext);
    Ok(record)
}

/// Decrypts a `nonce || ciphertext+tag` record, requiring `aad_key` to
/// match the associated data it was encrypted with. Any failure — wrong
/// key, tampered ciphertext, or a record moved onto the wrong filename —
/// comes back as one opaque [`SecretError::Other`]; the AEAD tag failing to
/// verify never leaks which part was wrong.
fn decrypt_record(
    master_key: &MasterKey,
    aad_key: &str,
    record: &[u8],
) -> Result<Vec<u8>, SecretError> {
    if record.len() < NONCE_LEN {
        return Err(SecretError::Other("secret record is truncated".to_string()));
    }
    let (nonce_bytes, ciphertext) = record.split_at(NONCE_LEN);
    let nonce = <&XNonce>::try_from(nonce_bytes)
        .map_err(|_| SecretError::Other("secret record nonce has unexpected length".to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: aad_key.as_bytes(),
    };
    cipher_for(master_key)?.decrypt(nonce, payload).map_err(|_| {
        SecretError::Other(
            "failed to decrypt secret (tampered ciphertext, wrong key, or record moved to a different key)"
                .to_string(),
        )
    })
}

/// Writes `data` to `path` atomically: a mode-0600 temp file is created in
/// the same directory (so the rename is same-filesystem and instant), the
/// mode is set at creation before any bytes are written, and the temp file
/// is renamed over the destination so a reader never observes a
/// partially-written record.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), SecretError> {
    let dir = path.parent().ok_or_else(|| {
        SecretError::Other(format!(
            "secret path {} has no parent directory",
            path.display()
        ))
    })?;

    let (mut file, tmp_path) = create_temp_file(dir).map_err(|err| {
        SecretError::Other(format!(
            "failed to create temp file in {}: {err}",
            dir.display()
        ))
    })?;

    if let Err(err) = file.write_all(data).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SecretError::Other(format!(
            "failed to write temp file {}: {err}",
            tmp_path.display()
        )));
    }
    drop(file);

    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        SecretError::Other(format!(
            "failed to rename {} to {}: {err}",
            tmp_path.display(),
            path.display()
        ))
    })
}

/// Creates a uniquely-named `.secret-tmp-*` file in `dir`, mode 0600 applied
/// at creation, and returns it along with its path.
fn create_temp_file(dir: &Path) -> std::io::Result<(File, PathBuf)> {
    const MAX_ATTEMPTS: u32 = 100;

    let mut attempt = 0;
    while attempt < MAX_ATTEMPTS {
        let path = dir.join(format!(".secret-tmp-{}", random_suffix()));
        match create_owner_only_file(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file after 100 attempts",
    ))
}

/// A random hex suffix for temp file names.
fn random_suffix() -> String {
    let value: u64 = rand::rng().random();
    format!("{value:x}")
}

/// Creates `path` with mode 0600 applied at creation, failing if it already
/// exists. A no-op mode on non-Unix targets, where this bit pattern has no
/// equivalent.
#[cfg(unix)]
fn create_owner_only_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Non-Unix stub for [`create_owner_only_file`]; see its doc.
#[cfg(not(unix))]
fn create_owner_only_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Creates `dir` (and any missing parents) with mode 0700 if it does not
/// already exist. An existing directory's mode is left untouched — its
/// world-writable status is [`ensure_master_key`]'s job to reject.
#[cfg(unix)]
fn create_owner_only_dir(dir: &Path) -> Result<(), SecretError> {
    use std::os::unix::fs::DirBuilderExt as _;
    if dir.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir).map_err(|err| {
        SecretError::Other(format!(
            "failed to create directory {}: {err}",
            dir.display()
        ))
    })
}

/// Non-Unix stub for [`create_owner_only_dir`]; see its doc.
#[cfg(not(unix))]
fn create_owner_only_dir(dir: &Path) -> Result<(), SecretError> {
    if dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|err| {
        SecretError::Other(format!(
            "failed to create directory {}: {err}",
            dir.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_backend() -> (tempfile::TempDir, FileBackend) {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = FileBackend::open(dir.path().to_path_buf()).expect("open file backend");
        (dir, backend)
    }

    #[test]
    fn round_trip_set_get_delete() {
        let (_dir, backend) = open_backend();

        backend.set("k", b"hello world").expect("set");
        let got = backend.get("k").expect("get");
        assert_eq!(got, b"hello world");

        backend.delete("k").expect("delete");
        let err = backend.get("k").expect_err("get after delete should fail");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[test]
    fn get_missing_key_is_not_found() {
        let (_dir, backend) = open_backend();
        let err = backend
            .get("does-not-exist")
            .expect_err("missing key should error");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[test]
    fn delete_missing_key_is_not_found() {
        let (_dir, backend) = open_backend();
        let err = backend
            .delete("does-not-exist")
            .expect_err("deleting a missing key should error");
        assert!(matches!(err, SecretError::NotFound));
    }

    #[test]
    fn aad_binding_rejects_a_record_moved_to_a_different_key() {
        let (_dir, backend) = open_backend();
        backend.set("key-a", b"secret-a").expect("set key-a");

        let raw = fs::read(backend.test_record_path("key-a")).expect("read raw record");
        // Copy key-a's raw (still valid) ciphertext onto key-b's filename —
        // simulating a move/rename at the storage layer.
        fs::write(backend.test_record_path("key-b"), &raw).expect("write raw record under key-b");

        let err = backend
            .get("key-b")
            .expect_err("a record encrypted for a different key must not decrypt");
        assert!(matches!(err, SecretError::Other(_)));
    }

    #[test]
    fn tampering_a_single_ciphertext_byte_fails_decryption() {
        let (_dir, backend) = open_backend();
        backend.set("k", b"do not tamper with me").expect("set");

        let path = backend.test_record_path("k");
        let mut raw = fs::read(&path).expect("read raw record");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF; // flip a byte inside the ciphertext/tag region
        fs::write(&path, &raw).expect("write tampered record");

        let err = backend
            .get("k")
            .expect_err("tampered ciphertext must not decrypt");
        assert!(matches!(err, SecretError::Other(_)));
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let (_dir, backend) = open_backend();

        backend.set("k", b"same plaintext").expect("first set");
        let first = fs::read(backend.test_record_path("k")).expect("read first record");

        backend.set("k", b"same plaintext").expect("second set");
        let second = fs::read(backend.test_record_path("k")).expect("read second record");

        assert_ne!(
            first, second,
            "re-encrypting identical plaintext must not produce identical records"
        );
        // Confirm it's specifically the nonce prefix that differs, not just
        // an incidental difference elsewhere.
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
    }

    #[cfg(unix)]
    #[test]
    fn stored_secret_file_has_mode_0600() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, backend) = open_backend();
        backend.set("k", b"value").expect("set");

        let mode = fs::metadata(backend.test_record_path("k"))
            .expect("stat")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
