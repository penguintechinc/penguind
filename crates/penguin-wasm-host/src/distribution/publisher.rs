//! Stages built module binaries and manifests for release.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;

/// Writes artifacts under `<base>/packages`.
pub struct Publisher {
    base_path: PathBuf,
}

impl Publisher {
    /// Creates a publisher rooted at `base_path`.
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Copies a built binary into the packages directory. `name` must be a
    /// plain file name (see [`validate_name`]); anything else is rejected.
    pub fn publish_binary(&self, source: &Path, name: &str) -> io::Result<PathBuf> {
        let target = self.target_for(name)?;
        fs::copy(source, &target)?;
        tracing::info!(name, "published module binary");
        Ok(target)
    }

    /// Writes a minimal `<name>.json` manifest next to the binary.
    pub fn generate_manifest(&self, name: &str, version: &str) -> io::Result<PathBuf> {
        let target = self.target_for(&format!("{name}.json"))?;
        let body = json!({ "name": name, "version": version, "type": "wasm_module" });
        fs::write(&target, serde_json::to_vec_pretty(&body)?)?;
        Ok(target)
    }

    /// Resolves `file_name` inside the packages dir, proving by canonical path
    /// that it cannot escape it (traversal, absolute names, symlinks).
    fn target_for(&self, file_name: &str) -> io::Result<PathBuf> {
        validate_name(file_name)?;
        let dir = self.base_path.join("packages");
        fs::create_dir_all(&dir)?;
        let canonical_dir = dir.canonicalize()?;
        let target = canonical_dir.join(file_name);
        if let Ok(meta) = fs::symlink_metadata(&target)
            && meta.file_type().is_symlink()
        {
            return Err(invalid("target is a symlink"));
        }
        match target.parent().map(Path::canonicalize) {
            Some(Ok(parent)) if parent == canonical_dir => Ok(target),
            _ => Err(invalid("target escapes the packages directory")),
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

/// Accepts only `[A-Za-z0-9._-]` (max 128 chars), not starting with `.`, so
/// `..`, separators and hidden files are all rejected.
pub fn validate_name(name: &str) -> io::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(invalid("invalid module name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_written() {
        let dir = std::env::temp_dir().join(format!("pwh-pub-{}", std::process::id()));
        let publisher = Publisher::new(dir.clone());
        let path = publisher.generate_manifest("m", "1.0.0").expect("write");
        let text = fs::read_to_string(path).expect("read");
        assert!(text.contains("wasm_module"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn traversal_names_are_rejected() {
        // regression: unsanitised `name` allowed path traversal.
        let dir = std::env::temp_dir().join(format!("pwh-trav-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let src = dir.join("src.wasm");
        fs::write(&src, b"x").expect("src");
        let publisher = Publisher::new(dir.clone());
        for bad in [
            "../evil", "..", ".", "a/b", "a\\b", "/abs", "", ".hidden", "a\0b", "a b",
        ] {
            assert!(publisher.publish_binary(&src, bad).is_err(), "{bad:?}");
            assert!(publisher.generate_manifest(bad, "1").is_err(), "{bad:?}");
        }
        assert!(!dir.join("evil").exists());
        assert!(publisher.publish_binary(&src, "ok-1.0_x.wasm").is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_is_rejected() {
        let dir = std::env::temp_dir().join(format!("pwh-sym-{}", std::process::id()));
        let outside = dir.join("outside");
        fs::create_dir_all(dir.join("packages")).expect("dir");
        fs::write(&outside, b"orig").expect("outside");
        std::os::unix::fs::symlink(&outside, dir.join("packages/link")).expect("symlink");
        let src = dir.join("src.wasm");
        fs::write(&src, b"new").expect("src");
        assert!(
            Publisher::new(dir.clone())
                .publish_binary(&src, "link")
                .is_err()
        );
        assert_eq!(fs::read(&outside).expect("read"), b"orig");
        let _ = fs::remove_dir_all(dir);
    }
}
