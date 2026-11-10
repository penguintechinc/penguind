//! Process-wide rustls crypto provider setup shared by every outbound HTTP client.

/// Installs the aws-lc-rs rustls provider if none is set yet. reqwest is built
/// with `rustls-no-provider`, and building a `Client` without a provider
/// panics, so every client constructor calls this first. Idempotent; the
/// "already installed" error is the expected second-call outcome.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::ensure_crypto_provider;

    #[test]
    fn installs_once_and_is_idempotent() {
        ensure_crypto_provider();
        ensure_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
