//! Binary extraction from a downloaded release archive.
//!
//! Both archive formats goreleaser produces are implemented: tar+gzip
//! (Linux/macOS) and zip (Windows, via `.goreleaser.yaml`'s
//! `format_overrides`). The Go reference implementation only ever handled
//! tar+gzip, which silently broke every Windows self-update — there was no
//! zip branch at all, just a single hardcoded `gzip.NewReader` call.
//!
//! Entries are matched by exact basename equality against the expected
//! binary filename (nested paths like `bin/penguind` still match on their
//! basename), never Go's loose `isBinaryName` prefix/regex heuristic —
//! `penguind` must never accidentally pick up an unrelated file that merely
//! starts with the same characters.

use std::io::{Cursor, Read};
use std::path::Path;

use crate::platform::ArchiveFormat;

/// Every way [`extract_binary`] can fail to produce the requested binary's
/// bytes.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// The bytes are not a valid gzip stream, or the tar stream inside it
    /// could not be read (corrupt archive, truncated download, ...).
    #[error("failed to read tar.gz archive: {0}")]
    TarRead(#[source] std::io::Error),
    /// The bytes are not a valid zip archive.
    #[error("failed to read zip archive: {0}")]
    ZipRead(#[source] zip::result::ZipError),
    /// The matching entry was found but its contents could not be read.
    #[error("failed to read entry {0:?} from archive: {1}")]
    EntryRead(String, #[source] std::io::Error),
    /// No entry in the archive has `binary_name` as its basename.
    #[error("no entry named {0:?} found in archive")]
    BinaryNotFound(String),
}

/// Extracts the entry whose basename equals `binary_name` from
/// `archive_bytes`, dispatching on `format`.
pub fn extract_binary(
    archive_bytes: &[u8],
    format: ArchiveFormat,
    binary_name: &str,
) -> Result<Vec<u8>, ArchiveError> {
    match format {
        ArchiveFormat::TarGz => extract_from_tar_gz(archive_bytes, binary_name),
        ArchiveFormat::Zip => extract_from_zip(archive_bytes, binary_name),
    }
}

/// True if `entry_name`'s basename (the part after the last `/`) equals
/// `binary_name` exactly.
fn basename_matches(entry_name: &str, binary_name: &str) -> bool {
    Path::new(entry_name)
        .file_name()
        .and_then(|name| name.to_str())
        == Some(binary_name)
}

fn extract_from_tar_gz(bytes: &[u8], binary_name: &str) -> Result<Vec<u8>, ArchiveError> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    let entries = archive.entries().map_err(ArchiveError::TarRead)?;

    for entry in entries {
        let mut entry = entry.map_err(ArchiveError::TarRead)?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let matches = {
            let path = entry.path().map_err(ArchiveError::TarRead)?;
            path.to_str()
                .map(|name| basename_matches(name, binary_name))
                .unwrap_or(false)
        };
        if !matches {
            continue;
        }

        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|err| ArchiveError::EntryRead(binary_name.to_string(), err))?;
        return Ok(contents);
    }

    Err(ArchiveError::BinaryNotFound(binary_name.to_string()))
}

fn extract_from_zip(bytes: &[u8], binary_name: &str) -> Result<Vec<u8>, ArchiveError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(ArchiveError::ZipRead)?;

    for index in 0..archive.len() {
        let mut file = archive.by_index(index).map_err(ArchiveError::ZipRead)?;
        if !file.is_file() {
            continue;
        }

        // zip 9: name() is fallible; an undecodable entry name cannot match the binary.
        let matches = file
            .name()
            .map(|name| basename_matches(&name, binary_name))
            .unwrap_or(false);
        if !matches {
            continue;
        }

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|err| ArchiveError::EntryRead(binary_name.to_string(), err))?;
        return Ok(contents);
    }

    Err(ArchiveError::BinaryNotFound(binary_name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an in-memory tar.gz archive from `(entry_name, contents)`
    /// pairs, mirroring the Go reference test suite's `createTestArchive`
    /// helper.
    fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gz_writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(gz_writer);
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, *name, *contents)
                .expect("append tar entry");
        }
        let gz_writer = builder.into_inner().expect("finish tar builder");
        gz_writer.finish().expect("finish gzip stream")
    }

    /// Builds an in-memory zip archive from `(entry_name, contents)` pairs.
    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start zip entry");
            std::io::Write::write_all(&mut writer, contents).expect("write zip entry contents");
        }
        writer.finish().expect("finish zip archive").into_inner()
    }

    #[test]
    fn extracts_binary_from_tar_gz_archive_root() {
        let archive = build_tar_gz(&[("penguind", b"binary content")]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::TarGz, "penguind").expect("extraction");
        assert_eq!(extracted, b"binary content");
    }

    #[test]
    fn extracts_binary_from_nested_tar_gz_path_by_basename() {
        let archive = build_tar_gz(&[("bin/penguind", b"nested binary")]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::TarGz, "penguind").expect("extraction");
        assert_eq!(extracted, b"nested binary");
    }

    #[test]
    fn tar_gz_ignores_unrelated_entries_and_finds_the_right_one() {
        let archive = build_tar_gz(&[
            ("README.md", b"docs"),
            ("penguin", b"cli binary"),
            ("penguind", b"daemon binary"),
        ]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::TarGz, "penguind").expect("extraction");
        assert_eq!(extracted, b"daemon binary");
    }

    #[test]
    fn tar_gz_never_prefix_matches_a_similarly_named_entry() {
        // Go's `isBinaryName` accepted anything with a "penguin_" prefix or
        // matching `^penguin\w*$` — "penguind-debug" would have passed.
        // Exact basename equality must reject it.
        let archive = build_tar_gz(&[("penguind-debug", b"decoy")]);
        let err = extract_binary(&archive, ArchiveFormat::TarGz, "penguind")
            .expect_err("must not prefix-match");
        assert!(matches!(err, ArchiveError::BinaryNotFound(name) if name == "penguind"));
    }

    #[test]
    fn tar_gz_reports_binary_not_found_when_absent() {
        let archive = build_tar_gz(&[("readme.txt", b"not a binary")]);
        let err = extract_binary(&archive, ArchiveFormat::TarGz, "penguind")
            .expect_err("no matching entry");
        assert!(matches!(err, ArchiveError::BinaryNotFound(_)));
    }

    #[test]
    fn tar_gz_rejects_invalid_gzip_data() {
        let err = extract_binary(b"not gzip data", ArchiveFormat::TarGz, "penguind")
            .expect_err("invalid gzip");
        assert!(matches!(err, ArchiveError::TarRead(_)));
    }

    #[test]
    fn tar_gz_rejects_valid_gzip_with_invalid_tar_contents() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, b"not a tar stream").expect("write raw bytes");
        let bytes = encoder.finish().expect("finish gzip stream");

        let err = extract_binary(&bytes, ArchiveFormat::TarGz, "penguind")
            .expect_err("gzip valid but tar contents are garbage");
        assert!(matches!(err, ArchiveError::TarRead(_)));
    }

    #[test]
    fn extracts_binary_from_zip_archive_root() {
        let archive = build_zip(&[("penguind.exe", b"windows binary")]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::Zip, "penguind.exe").expect("extraction");
        assert_eq!(extracted, b"windows binary");
    }

    #[test]
    fn extracts_binary_from_nested_zip_path_by_basename() {
        let archive = build_zip(&[("bin/penguind.exe", b"nested windows binary")]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::Zip, "penguind.exe").expect("extraction");
        assert_eq!(extracted, b"nested windows binary");
    }

    #[test]
    fn zip_ignores_unrelated_entries_and_finds_the_right_one() {
        let archive = build_zip(&[
            ("README.md", b"docs"),
            ("penguin.exe", b"cli binary"),
            ("penguind.exe", b"daemon binary"),
        ]);
        let extracted =
            extract_binary(&archive, ArchiveFormat::Zip, "penguind.exe").expect("extraction");
        assert_eq!(extracted, b"daemon binary");
    }

    #[test]
    fn zip_reports_binary_not_found_when_absent() {
        let archive = build_zip(&[("readme.txt", b"not a binary")]);
        let err = extract_binary(&archive, ArchiveFormat::Zip, "penguind.exe")
            .expect_err("no matching entry");
        assert!(matches!(err, ArchiveError::BinaryNotFound(_)));
    }

    #[test]
    fn zip_rejects_invalid_archive_data() {
        let err = extract_binary(b"not a zip file", ArchiveFormat::Zip, "penguind.exe")
            .expect_err("invalid zip");
        assert!(matches!(err, ArchiveError::ZipRead(_)));
    }
}
