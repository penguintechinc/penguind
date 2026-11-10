//! Integrity checks for downloaded module binaries.

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

/// Why a module failed verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    /// The SHA-256 digest differs from the manifest.
    #[error("SHA256 hash mismatch")]
    HashMismatch,
    /// The signature or key is malformed, or does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// The manifest's id or version is not the one the caller asked for
    /// (a replayed older release).
    #[error("manifest does not match the expected module id/version")]
    ManifestMismatch,
    /// An id, version or digest field is malformed (empty, control characters,
    /// or not lowercase-hex SHA-256), so it cannot be bound into a signature.
    #[error("malformed manifest field")]
    MalformedField,
}

/// Checks the binary's SHA-256 (lowercase hex) against the manifest value.
pub fn verify_hash(binary: &[u8], expected_hex: &str) -> Result<(), VerificationError> {
    let digest = Sha256::digest(binary);
    let mut actual = String::with_capacity(64);
    for byte in digest {
        actual.push_str(&format!("{byte:02x}"));
    }
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(VerificationError::HashMismatch)
    }
}

/// Verifies a minisign signature over arbitrary bytes. Low level: it proves
/// nothing about id/version, so production code uses [`VerifiedModule::verify`].
pub fn verify_signature(
    binary: &[u8],
    signature_text: &str,
    public_key_text: &str,
) -> Result<(), VerificationError> {
    let key =
        PublicKey::decode(public_key_text).map_err(|_| VerificationError::InvalidSignature)?;
    let sig = Signature::decode(signature_text).map_err(|_| VerificationError::InvalidSignature)?;
    key.verify(binary, &sig, false)
        .map_err(|_| VerificationError::InvalidSignature)
}

fn field_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

/// Canonical signed payload binding module id, version and binary digest, so a
/// signature for one release can never validate another id, version or binary.
pub fn signed_payload(
    id: &str,
    version: &str,
    sha256_hex: &str,
) -> Result<Vec<u8>, VerificationError> {
    let hex_ok = sha256_hex.len() == 64
        && sha256_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !field_ok(id) || !field_ok(version) || !hex_ok {
        return Err(VerificationError::MalformedField);
    }
    Ok(
        format!("penguin-wasm-module/v1\nid={id}\nversion={version}\nsha256={sha256_hex}\n")
            .into_bytes(),
    )
}

/// The untrusted manifest fields a signature must cover.
#[derive(Debug, Clone, Copy)]
pub struct ManifestClaims<'a> {
    /// Claimed module id.
    pub id: &'a str,
    /// Claimed module version.
    pub version: &'a str,
    /// Claimed lowercase-hex SHA-256 of the binary.
    pub sha256: &'a str,
    /// Minisign signature text.
    pub signature: &'a str,
}

/// A module binary whose id, version and SHA-256 were signed by a pinned
/// minisign key. The only constructor is [`VerifiedModule::verify`], so holding
/// one is proof the check ran; `WasmRuntime::run_verified` accepts nothing else.
#[derive(Debug)]
pub struct VerifiedModule {
    id: String,
    version: String,
    sha256: String,
    bytes: Vec<u8>,
}

impl VerifiedModule {
    /// Verifies `binary` against the manifest fields and the signature, using
    /// the pinned `public_key_text`. The manifest id/version must equal the
    /// caller's `expected_*` and the signature must cover id+version+sha256.
    pub fn verify(
        expected_id: &str,
        expected_version: &str,
        claims: &ManifestClaims<'_>,
        binary: Vec<u8>,
        public_key_text: &str,
    ) -> Result<Self, VerificationError> {
        let ManifestClaims {
            id: manifest_id,
            version: manifest_version,
            sha256: manifest_sha256,
            signature: signature_text,
        } = *claims;
        if manifest_id != expected_id || manifest_version != expected_version {
            return Err(VerificationError::ManifestMismatch);
        }
        let sha256 = manifest_sha256.to_ascii_lowercase();
        let payload = signed_payload(manifest_id, manifest_version, &sha256)?;
        verify_signature(&payload, signature_text, public_key_text)?;
        verify_hash(&binary, &sha256)?;
        Ok(Self {
            id: manifest_id.to_string(),
            version: manifest_version.to_string(),
            sha256,
            bytes: binary,
        })
    }

    /// The verified module id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The verified module version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The verified lowercase-hex SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The verified binary.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Minisign fixtures: keys A/B and a signature by each over
    //! id=demo, version=1.0.0, sha256 of [`BINARY`].
    pub const BINARY: &[u8] = b"\0asm\x01\0\0\0";
    pub const SHA: &str = "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476";
    pub const PUB_A: &str =
        "untrusted comment: test\nRWQBAgMEBQYHCIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c";
    pub const SIG_A: &str = "untrusted comment: sig\nRUQBAgMEBQYHCCLucues8Fr7cm3jNC9vFcTrCss+krInWk0XLem0ETXzlCXjDZAQvgpJjKQ8dtgsr1sTQwQ5YpJcL5fN/YgIYAI=\ntrusted comment: t\nQxCm3/A7xy5j3v85YZFwwjOVlSL/0XRrGcleGwSMOZ03HWWyZUNoPrnyshMJc6ynCAyml7wqTfyY61v7/j3kCw==\n";
    pub const SIG_B: &str = "untrusted comment: sig\nRUQLDA0ODxAREm9dsCNLFMArSiLVdTUjNwxpRFxjycKQO0YfnXTCNtqn6pswzQw7XhvBZqFER5O6vmkBK928qKUNnzy4lgLOnQ8=\ntrusted comment: t\naER1zgmjTgFWjgVT+xCbnvsCd4pYL1puk3TRYtBtv+6FjnGSAa6l3amfGz1cRuO6Fthdv/B0mOVbpJSSypM2DQ==\n";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn verify(
        ver: &str,
        sig: &str,
        bin: &[u8],
        expect_ver: &str,
    ) -> Result<VerifiedModule, VerificationError> {
        VerifiedModule::verify(
            "demo",
            expect_ver,
            &ManifestClaims {
                id: "demo",
                version: ver,
                sha256: SHA,
                signature: sig,
            },
            bin.to_vec(),
            PUB_A,
        )
    }

    #[test]
    fn valid_signature_yields_verified_module() {
        let m = verify("1.0.0", SIG_A, BINARY, "1.0.0").expect("verifies");
        assert_eq!(
            (m.id(), m.version(), m.as_bytes()),
            ("demo", "1.0.0", BINARY)
        );
    }

    #[test]
    fn replayed_old_release_fails() {
        // regression: old signed binary replayed as a newer version.
        assert_eq!(
            verify("1.0.0", SIG_A, BINARY, "2.0.0").unwrap_err(),
            VerificationError::ManifestMismatch
        );
        // attacker relabels the manifest version; the signature binds the version.
        assert_eq!(
            verify("2.0.0", SIG_A, BINARY, "2.0.0").unwrap_err(),
            VerificationError::InvalidSignature
        );
    }

    #[test]
    fn signature_from_other_key_fails() {
        assert_eq!(
            verify("1.0.0", SIG_B, BINARY, "1.0.0").unwrap_err(),
            VerificationError::InvalidSignature
        );
    }

    #[test]
    fn tampered_binary_fails_hash() {
        assert_eq!(
            verify("1.0.0", SIG_A, b"other", "1.0.0").unwrap_err(),
            VerificationError::HashMismatch
        );
    }

    #[test]
    fn malformed_fields_cannot_be_bound() {
        assert_eq!(
            signed_payload("a\nb", "1", SHA),
            Err(VerificationError::MalformedField)
        );
        assert_eq!(
            signed_payload("a", "1", "xyz"),
            Err(VerificationError::MalformedField)
        );
    }

    #[test]
    fn hash_matches_and_mismatches() {
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(verify_hash(b"", empty), Ok(()));
        assert_eq!(
            verify_hash(b"x", empty),
            Err(VerificationError::HashMismatch)
        );
    }

    #[test]
    fn malformed_signature_is_rejected() {
        assert_eq!(
            verify_signature(b"x", "junk", "junk"),
            Err(VerificationError::InvalidSignature)
        );
    }
}
