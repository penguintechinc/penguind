//! The persisted set of user-enabled modules, ported from
//! `go-client/internal/daemon/state.go`.
//!
//! # Restart-persistence rule
//!
//! Daemon shutdown must NEVER call [`PersistedState::save`] to drop a name
//! from this file — only an explicit Unload does that. That is the sole
//! mechanism that makes "restart brings back what was loaded" work: the file
//! only shrinks in response to a deliberate user action, never a process
//! exit. Anything that persists state as part of a shutdown path is a bug.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use rand::Rng;
use serde::{Deserialize, Serialize};

/// The set of modules the user has enabled, loaded from and saved to
/// `<state_dir>/enabled.json`.
///
/// Wire schema is exactly `{ "enabled": [...] }` — the field name and set are
/// the only thing on disk. A [`BTreeSet`] backs it so the serialized array is
/// always in a deterministic (sorted) order regardless of insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    enabled: BTreeSet<String>,
}

/// An error loading or saving [`PersistedState`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// A filesystem operation (read, write, chmod, rename, mkdir) failed.
    #[error("{0}")]
    Io(String),
    /// The state file existed but was not valid JSON for [`PersistedState`].
    #[error("{0}")]
    Parse(String),
}

impl PersistedState {
    /// Loads the state from `<state_dir>/enabled.json`.
    ///
    /// A missing file or an empty file both yield an empty set — this is the
    /// expected state on first run, not an error. A present-but-malformed
    /// file is [`StateError::Parse`].
    pub fn load(state_dir: &Path) -> Result<PersistedState, StateError> {
        let path = enabled_path(state_dir);

        let data = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(PersistedState::default()),
            Err(err) => return Err(StateError::Io(format!("read {path:?}: {err}"))),
        };
        if data.is_empty() {
            return Ok(PersistedState::default());
        }

        serde_json::from_slice(&data)
            .map_err(|err| StateError::Parse(format!("parse {path:?}: {err}")))
    }

    /// Persists the state to `<state_dir>/enabled.json` atomically: a
    /// mode-0600 temp file is written in `state_dir` and then renamed over
    /// the destination, so a reader never observes a partially-written file.
    ///
    /// The parent directory is created (mode 0700) if it does not exist. On
    /// any write or permission error the temp file is removed before the
    /// error is returned.
    pub fn save(&self, state_dir: &Path) -> Result<(), StateError> {
        ensure_state_dir(state_dir)?;

        // 2-space-indented pretty JSON, matching Go's
        // `json.MarshalIndent(ps, "", "  ")` for byte parity.
        let data = serde_json::to_vec_pretty(self)
            .map_err(|err| StateError::Io(format!("marshal enabled.json: {err}")))?;

        let (mut file, tmp_path) = create_temp_file(state_dir)
            .map_err(|err| StateError::Io(format!("create temp file in {state_dir:?}: {err}")))?;

        if let Err(err) = set_owner_read_write(&file) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(StateError::Io(format!("chmod {tmp_path:?}: {err}")));
        }

        if let Err(err) = file.write_all(&data) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(StateError::Io(format!("write {tmp_path:?}: {err}")));
        }
        drop(file);

        let path = enabled_path(state_dir);
        std::fs::rename(&tmp_path, &path)
            .map_err(|err| StateError::Io(format!("rename {tmp_path:?} -> {path:?}: {err}")))
    }

    /// Adds `name` to the enabled set. Returns `true` if it was not already
    /// present.
    pub fn add(&mut self, name: &str) -> bool {
        self.enabled.insert(name.to_string())
    }

    /// Removes `name` from the enabled set. Returns `true` if it was present.
    pub fn remove(&mut self, name: &str) -> bool {
        self.enabled.remove(name)
    }

    /// Reports whether `name` is currently enabled.
    pub fn contains(&self, name: &str) -> bool {
        self.enabled.contains(name)
    }

    /// Iterates the enabled set in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.enabled.iter()
    }
}

/// Builds the on-disk path for the state file.
fn enabled_path(state_dir: &Path) -> PathBuf {
    state_dir.join("enabled.json")
}

/// Creates `state_dir` (and any missing parents) with mode 0700 if it does
/// not already exist. An existing directory's mode is left untouched,
/// matching Go's `os.MkdirAll` semantics.
fn ensure_state_dir(state_dir: &Path) -> Result<(), StateError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    set_dir_builder_mode(&mut builder);
    builder
        .create(state_dir)
        .map_err(|err| StateError::Io(format!("create state dir {state_dir:?}: {err}")))
}

/// Applies the 0700 owner-only mode to directories a [`std::fs::DirBuilder`]
/// creates. A no-op on non-Unix targets, where this bit pattern has no
/// equivalent.
#[cfg(unix)]
fn set_dir_builder_mode(builder: &mut std::fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700);
}

/// Non-Unix stub for [`set_dir_builder_mode`]; see its doc.
#[cfg(not(unix))]
fn set_dir_builder_mode(_builder: &mut std::fs::DirBuilder) {}

/// Creates a uniquely-named `.state-tmp-*` file in `dir` and returns it along
/// with its path, mirroring Go's `os.CreateTemp(dir, ".state-tmp-*")`.
fn create_temp_file(dir: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    const MAX_ATTEMPTS: u32 = 100;

    let mut attempt = 0;
    while attempt < MAX_ATTEMPTS {
        let path = dir.join(format!(".state-tmp-{}", random_suffix()));
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path);
        match opened {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => attempt += 1,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "could not create a unique temp file after 100 attempts",
    ))
}

/// Generates a random hex suffix for a temp file name.
fn random_suffix() -> String {
    let value: u64 = rand::rng().random();
    format!("{value:x}")
}

/// Sets a file's mode to 0600 (owner read/write only). A no-op on non-Unix
/// targets, where this bit pattern has no equivalent.
#[cfg(unix)]
fn set_owner_read_write(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

/// Non-Unix stub for [`set_owner_read_write`]; see its doc.
#[cfg(not(unix))]
fn set_owner_read_write(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = TempDir::new().unwrap();
        let state = PersistedState::load(dir.path()).unwrap();
        assert!(state.iter().next().is_none());
    }

    #[test]
    fn empty_file_loads_as_empty() {
        let dir = TempDir::new().unwrap();
        std::fs::write(enabled_path(dir.path()), b"").unwrap();
        let state = PersistedState::load(dir.path()).unwrap();
        assert!(state.iter().next().is_none());
    }

    #[test]
    fn corrupt_json_is_an_error() {
        let dir = TempDir::new().unwrap();
        std::fs::write(enabled_path(dir.path()), b"{ not json").unwrap();
        assert!(matches!(
            PersistedState::load(dir.path()),
            Err(StateError::Parse(_))
        ));
    }

    #[test]
    fn round_trips_through_save_and_load() {
        let dir = TempDir::new().unwrap();
        let mut state = PersistedState::default();
        state.add("squawk");
        state.add("waddles-gateway");
        state.save(dir.path()).unwrap();

        let loaded = PersistedState::load(dir.path()).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn add_remove_and_contains() {
        let mut state = PersistedState::default();
        assert!(!state.contains("squawk"));
        assert!(state.add("squawk"));
        assert!(!state.add("squawk")); // already present
        assert!(state.contains("squawk"));
        assert!(state.remove("squawk"));
        assert!(!state.remove("squawk")); // already absent
        assert!(!state.contains("squawk"));
    }

    #[test]
    fn serialized_order_is_deterministic_regardless_of_insertion_order() {
        let mut a = PersistedState::default();
        a.add("waddles-gateway");
        a.add("squawk");
        a.add("marchproxy");

        let mut b = PersistedState::default();
        b.add("squawk");
        b.add("marchproxy");
        b.add("waddles-gateway");

        let dir = TempDir::new().unwrap();
        a.save(dir.path()).unwrap();
        let bytes_a = std::fs::read(enabled_path(dir.path())).unwrap();
        b.save(dir.path()).unwrap();
        let bytes_b = std::fs::read(enabled_path(dir.path())).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn save_uses_two_space_indented_json() {
        let dir = TempDir::new().unwrap();
        let mut state = PersistedState::default();
        state.add("squawk");
        state.save(dir.path()).unwrap();

        let text = std::fs::read_to_string(enabled_path(dir.path())).unwrap();
        assert_eq!(text, "{\n  \"enabled\": [\n    \"squawk\"\n  ]\n}");
    }

    #[cfg(unix)]
    #[test]
    fn state_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        PersistedState::default().save(dir.path()).unwrap();

        let mode = std::fs::metadata(enabled_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_is_created_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let root = TempDir::new().unwrap();
        let state_dir = root.path().join("nested").join("state");
        PersistedState::default().save(&state_dir).unwrap();

        let mode = std::fs::metadata(&state_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
