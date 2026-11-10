//! Offline cache: the last applied bundle (`hub-cache.json`, 0600, atomic
//! write) and verified binaries content-addressed by sha256. Nothing here is
//! trusted on load: the client re-verifies every module's signature and a
//! corrupt state file means deny-all, not "use defaults".

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::HubError;
use crate::model::SyncBundle;

/// File name of the state document inside the cache dir.
pub const STATE_FILE: &str = "hub-cache.json";
/// File name of the monotonic rollback high-water marks. Survives
/// [`HubCache::clear`] (revocation); only [`HubCache::reset_high_water`], an
/// explicit local operator action, removes entries.
pub const HIGH_WATER_FILE: &str = "hub-highwater.json";

/// What survives a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedState {
    /// ETag of the fully applied bundle; empty if the last apply was partial.
    pub etag: String,
    /// The bundle itself.
    pub bundle: SyncBundle,
    /// Unix seconds of the last successful hub contact.
    pub last_contact: i64,
    /// Highest verified version per module id (rollback protection).
    pub highest: BTreeMap<String, String>,
}

/// Result of reading the cache.
#[derive(Debug)]
pub enum CacheLoad {
    /// No cache file: first run.
    Missing,
    /// The file exists but is unreadable, unparsable, or not a regular file.
    Corrupt(String),
    /// A parsed state (modules are still unverified).
    Loaded(Box<CachedState>),
}

/// Handle on the cache directory.
pub struct HubCache {
    dir: PathBuf,
}

impl HubCache {
    /// Cache rooted at `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path of the state file.
    pub fn state_path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    fn blob_dir(&self) -> PathBuf {
        self.dir.join("hub-blobs")
    }

    /// Reads the state file. A symlink or non-regular file is `Corrupt`.
    pub fn load(&self) -> CacheLoad {
        let path = self.state_path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CacheLoad::Missing,
            Err(e) => return CacheLoad::Corrupt(e.to_string()),
        };
        if !meta.is_file() {
            return CacheLoad::Corrupt("not a regular file".into());
        }
        let raw = match fs::read(&path) {
            Ok(r) => r,
            Err(e) => return CacheLoad::Corrupt(e.to_string()),
        };
        match serde_json::from_slice::<CachedState>(&raw) {
            Ok(s) => CacheLoad::Loaded(Box::new(s)),
            Err(e) => CacheLoad::Corrupt(e.to_string()),
        }
    }

    /// Persists the state atomically with mode 0600.
    pub fn save(&self, state: &CachedState) -> Result<(), HubError> {
        let raw = serde_json::to_vec_pretty(state).map_err(|e| HubError::Cache(e.to_string()))?;
        write_atomic(&self.dir, &self.state_path(), &raw)
    }

    /// Stores a verified binary under its sha256 (lowercase hex).
    pub fn store_blob(&self, sha256: &str, bytes: &[u8]) -> Result<(), HubError> {
        let path = self.blob_path(sha256)?;
        write_atomic(&self.blob_dir(), &path, bytes)
    }

    /// Reads a cached binary; `None` when absent or oversize. The caller must
    /// re-verify it — the cache is not a trust anchor.
    pub fn read_blob(&self, sha256: &str, max: usize) -> Option<Vec<u8>> {
        let path = self.blob_path(sha256).ok()?;
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.len() > max as u64 {
            return None;
        }
        fs::read(path).ok()
    }

    /// Deletes every cached binary whose sha256 is not in `keep`.
    pub fn gc_blobs(&self, keep: &[String]) {
        let Ok(rd) = fs::read_dir(self.blob_dir()) else {
            return;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !keep.contains(&name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// Path of the high-water file.
    pub fn high_water_path(&self) -> PathBuf {
        self.dir.join(HIGH_WATER_FILE)
    }

    /// Reads the high-water marks; missing → empty. An unreadable or
    /// unparsable file is an error so the caller can keep what it has.
    pub fn load_high_water(&self) -> Result<BTreeMap<String, String>, HubError> {
        let path = self.high_water_path();
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(HubError::Cache("high-water: not a regular file".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(HubError::Cache(e.to_string())),
        }
        let raw = fs::read(&path).map_err(|e| HubError::Cache(e.to_string()))?;
        serde_json::from_slice(&raw).map_err(|e| HubError::Cache(e.to_string()))
    }

    /// Persists the high-water marks atomically (0600).
    pub fn save_high_water(&self, marks: &BTreeMap<String, String>) -> Result<(), HubError> {
        let raw = serde_json::to_vec_pretty(marks).map_err(|e| HubError::Cache(e.to_string()))?;
        write_atomic(&self.dir, &self.high_water_path(), &raw)
    }

    /// Explicit local operator action: forget the mark for `id`, or every
    /// mark when `id` is `None`. Never called by the sync path.
    pub fn reset_high_water(&self, id: Option<&str>) -> Result<(), HubError> {
        match id {
            None => match fs::remove_file(self.high_water_path()) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(HubError::Cache(e.to_string())),
            },
            Some(id) => {
                let mut marks = self.load_high_water()?;
                if marks.remove(id).is_some() {
                    self.save_high_water(&marks)?;
                }
                Ok(())
            }
        }
    }

    /// Removes the state file and every blob (revocation). The high-water
    /// file is deliberately kept.
    pub fn clear(&self) {
        let _ = fs::remove_file(self.state_path());
        let _ = fs::remove_dir_all(self.blob_dir());
    }

    /// Blob path for a validated digest; rejects anything but 64 lowercase hex.
    fn blob_path(&self, sha256: &str) -> Result<PathBuf, HubError> {
        let ok = sha256.len() == 64
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(HubError::Cache("invalid blob digest".into()));
        }
        Ok(self.blob_dir().join(sha256))
    }
}

/// Temp-file + fsync + rename in `dir`, mode 0600 set before any byte is written.
fn write_atomic(dir: &Path, dest: &Path, data: &[u8]) -> Result<(), HubError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let io = |e: std::io::Error| HubError::Cache(e.to_string());
    fs::create_dir_all(dir).map_err(io)?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> std::io::Result<()> {
        let mut f = create_private(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dest)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io(e));
    }
    Ok(())
}

/// Creates a new file readable only by the owner (0600 on Unix).
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Creates a new file; Windows relies on the directory ACL.
#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_water_survives_clear_and_resets_only_explicitly() {
        let dir = tempfile::tempdir().expect("tmp");
        let c = HubCache::new(dir.path());
        assert!(c.load_high_water().expect("empty").is_empty());
        let marks = BTreeMap::from([
            ("a".to_string(), "2.0.0".to_string()),
            ("b".to_string(), "1.0.0".to_string()),
        ]);
        c.save_high_water(&marks).expect("save");
        c.clear();
        assert_eq!(c.load_high_water().expect("kept"), marks);
        c.reset_high_water(Some("a")).expect("reset a");
        c.reset_high_water(Some("zz")).expect("absent id ok");
        assert_eq!(
            c.load_high_water().expect("b only"),
            BTreeMap::from([("b".to_string(), "1.0.0".to_string())])
        );
        c.reset_high_water(None).expect("reset all");
        c.reset_high_water(None).expect("idempotent");
        assert!(c.load_high_water().expect("empty").is_empty());
    }

    #[test]
    fn high_water_corrupt_or_non_file_is_error() {
        let dir = tempfile::tempdir().expect("tmp");
        let c = HubCache::new(dir.path());
        fs::write(c.high_water_path(), b"{nope").expect("w");
        assert!(c.load_high_water().is_err());
        assert!(c.reset_high_water(Some("a")).is_err());
        fs::remove_file(c.high_water_path()).expect("rm");
        fs::create_dir(c.high_water_path()).expect("dir");
        assert!(c.load_high_water().is_err());
        assert!(c.reset_high_water(None).is_err());
    }

    fn state() -> CachedState {
        CachedState {
            etag: "\"e1\"".into(),
            bundle: SyncBundle {
                agent_id: "a".into(),
                generated_at: "t".into(),
                policy: Default::default(),
                flags: Default::default(),
                modules: vec![],
                poll_interval_s: 300,
                max_stale_s: 600,
            },
            last_contact: 1_700_000_000,
            highest: BTreeMap::from([("m".to_string(), "1.0.0".to_string())]),
        }
    }

    const SHA: &str = "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";

    #[test]
    fn round_trip_is_0600_and_atomic() {
        let d = tempfile::tempdir().expect("tmp");
        let c = HubCache::new(d.path().join("sub"));
        assert!(matches!(c.load(), CacheLoad::Missing));
        c.save(&state()).expect("save");
        c.save(&state()).expect("overwrite");
        let CacheLoad::Loaded(got) = c.load() else {
            panic!("expected loaded");
        };
        assert_eq!(*got, state());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(c.state_path())
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let leftovers: Vec<_> = fs::read_dir(d.path().join("sub"))
            .expect("dir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn corrupt_and_non_file_states_are_reported() {
        let d = tempfile::tempdir().expect("tmp");
        let c = HubCache::new(d.path());
        fs::write(c.state_path(), b"{ not json").expect("write");
        assert!(matches!(c.load(), CacheLoad::Corrupt(_)));
        fs::remove_file(c.state_path()).expect("rm");
        fs::create_dir(c.state_path()).expect("dir");
        assert!(matches!(c.load(), CacheLoad::Corrupt(_)));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_is_corrupt() {
        let d = tempfile::tempdir().expect("tmp");
        let target = d.path().join("elsewhere.json");
        fs::write(&target, serde_json::to_vec(&state()).expect("json")).expect("write");
        let c = HubCache::new(d.path());
        std::os::unix::fs::symlink(&target, c.state_path()).expect("link");
        assert!(matches!(c.load(), CacheLoad::Corrupt(_)));
    }

    #[test]
    fn blobs_store_read_gc_and_reject_bad_digests() {
        let d = tempfile::tempdir().expect("tmp");
        let c = HubCache::new(d.path());
        assert!(c.store_blob("../etc/passwd", b"x").is_err());
        assert!(c.read_blob("zz", 10).is_none());
        c.store_blob(SHA, b"abc").expect("store");
        assert_eq!(c.read_blob(SHA, 10).as_deref(), Some(&b"abc"[..]));
        assert!(c.read_blob(SHA, 2).is_none(), "oversize refused");
        let other = "a".repeat(64);
        c.store_blob(&other, b"z").expect("store");
        c.gc_blobs(&[SHA.to_string()]);
        assert!(c.read_blob(&other, 10).is_none());
        assert!(c.read_blob(SHA, 10).is_some());
        c.clear();
        assert!(c.read_blob(SHA, 10).is_none());
        assert!(matches!(c.load(), CacheLoad::Missing));
        c.gc_blobs(&[]); // missing dir is fine
    }
}
