//! The bridge's per-script identity and bearer-token registry — the whole
//! reason a connecting integration script never sees the upstream Community
//! Access Token: a script proves itself with a narrow, local, revocable
//! credential *this* registry mints, not the CAT the module holds.
//!
//! Two lookup paths, one registry: [`TokenRegistry::authorize_token`] for
//! the TCP transport (a script presents a bearer token it was handed) and
//! [`TokenRegistry::identity_for_name`] for the unix transport (the OS
//! socket boundary already proved the connecting process is trusted, so a
//! script only needs to name itself — no secret required). Both paths
//! resolve to the same underlying grant: a name only has the scopes
//! [`TokenRegistry::register`] gave it, regardless of which door it walked
//! through.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex as StdMutex;

use rand::Rng;

use crate::bridge::scope::Scope;

/// A resolved, authenticated caller: which script it is and what it may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptIdentity {
    pub name: String,
    pub scopes: HashSet<Scope>,
}

/// A random per-script bearer token's prefix — not a secret format check
/// (the registry never accepts an unminted token regardless of prefix), just
/// a human-recognizable marker in logs/diagnostics that never carries the
/// module's CAT (`wdl_c_...`) prefix.
const TOKEN_PREFIX: &str = "wdlbridge_";

/// How many random bytes back a minted token, hex-encoded — 32 bytes is
/// 256 bits of entropy, comfortably beyond brute-force range for a
/// loopback-only credential.
const TOKEN_ENTROPY_BYTES: usize = 32;

#[derive(Default)]
struct RegistryInner {
    /// name -> the scopes it is allowed to hold. Populated by
    /// [`TokenRegistry::register`] — the allow-list gate both transports
    /// check against.
    scopes_by_name: HashMap<String, HashSet<Scope>>,
    /// bearer token -> name. A name has at most one live token; minting a
    /// new one for the same name invalidates whichever token it replaces.
    token_to_name: HashMap<String, String>,
}

/// The bridge's live registry of known integration names, their scopes, and
/// (for the TCP transport) their current bearer tokens. One instance is
/// shared by both transports via [`crate::bridge::state::BridgeState`].
///
/// Deliberately **in-memory only**, not persisted to `host.data_dir()` or
/// `host.secrets()`: a bridge restart re-derives the allow-list from
/// `bridge.allowed_integrations` and mints fresh tokens
/// ([`crate::bridge::start`]), so there is nothing a script could present
/// across a restart anyway — every old TCP token is implicitly revoked the
/// moment the bridge (or the daemon) restarts, which is the simpler and
/// safer default for a local, low-stakes credential. The unix transport is
/// unaffected either way, since it never depends on a stored secret.
#[derive(Default)]
pub struct TokenRegistry {
    inner: StdMutex<RegistryInner>,
}

impl TokenRegistry {
    pub fn new() -> TokenRegistry {
        TokenRegistry::default()
    }

    /// Declares `name` a known integration, holding exactly `scopes`.
    /// Re-registering an existing name replaces its scope grant (but not
    /// its current token, if any — mint a fresh one after narrowing a
    /// grant if the old token should stop working under the old scopes).
    pub fn register(&self, name: &str, scopes: HashSet<Scope>) {
        let mut inner = self.inner.lock().expect("token registry mutex poisoned");
        inner.scopes_by_name.insert(name.to_string(), scopes);
    }

    /// Mints and returns a fresh bearer token for `name`, replacing
    /// whichever token it previously held. Fails closed with `None` if
    /// `name` was never [`TokenRegistry::register`]ed — minting a token is
    /// never itself how a script becomes trusted, only how an already
    /// trusted (registered) one authenticates over TCP.
    pub fn mint(&self, name: &str) -> Option<String> {
        let mut inner = self.inner.lock().expect("token registry mutex poisoned");
        if !inner.scopes_by_name.contains_key(name) {
            return None;
        }
        inner.token_to_name.retain(|_token, owner| owner != name);
        let token = format!("{TOKEN_PREFIX}{}", random_hex(TOKEN_ENTROPY_BYTES));
        inner.token_to_name.insert(token.clone(), name.to_string());
        Some(token)
    }

    /// Revokes whichever token `name` currently holds, if any. `name`
    /// remains registered (still a valid target for a future
    /// [`TokenRegistry::mint`] or the unix transport's
    /// [`TokenRegistry::identity_for_name`]) — this only kills the TCP
    /// bearer credential, matching "revoke a token" rather than "remove an
    /// integration".
    // Reserved for a future operator-facing revoke path (e.g. a CLI
    // command); exercised directly by this module's own tests today.
    #[allow(dead_code)]
    pub fn revoke(&self, name: &str) {
        let mut inner = self.inner.lock().expect("token registry mutex poisoned");
        inner.token_to_name.retain(|_token, owner| owner != name);
    }

    /// TCP transport: resolves a live bearer token to its identity. `None`
    /// for an absent, revoked, or never-minted token — fail closed.
    pub fn authorize_token(&self, token: &str) -> Option<ScriptIdentity> {
        if token.is_empty() {
            return None;
        }
        let inner = self.inner.lock().expect("token registry mutex poisoned");
        let name = inner.token_to_name.get(token)?;
        let scopes = inner.scopes_by_name.get(name)?;
        Some(ScriptIdentity {
            name: name.clone(),
            scopes: scopes.clone(),
        })
    }

    /// Unix transport: resolves a *registered* name directly, no bearer
    /// token involved — the caller (a peer-cred-authorized local process)
    /// already crossed the OS trust boundary; this only confirms the name
    /// it claims is one `bridge.allowed_integrations` actually names.
    pub fn identity_for_name(&self, name: &str) -> Option<ScriptIdentity> {
        let inner = self.inner.lock().expect("token registry mutex poisoned");
        let scopes = inner.scopes_by_name.get(name)?;
        Some(ScriptIdentity {
            name: name.to_string(),
            scopes: scopes.clone(),
        })
    }
}

/// Renders `len` cryptographically random bytes as lowercase hex. No `hex`
/// crate in the workspace for this one call site, so this is hand-rolled
/// rather than pulling one in.
fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rng().fill(bytes.as_mut_slice());
    let mut hex = String::with_capacity(len * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_name_cannot_mint_a_token() {
        let registry = TokenRegistry::new();
        assert_eq!(registry.mint("ghost"), None);
    }

    #[test]
    fn registered_name_mints_a_token_that_authorizes_with_its_scopes() {
        let registry = TokenRegistry::new();
        let scopes = HashSet::from([Scope::BrowserSourceRead]);
        registry.register("obs-overlay", scopes.clone());

        let token = registry.mint("obs-overlay").expect("mint succeeds");
        assert!(token.starts_with(TOKEN_PREFIX));

        let identity = registry.authorize_token(&token).expect("token authorizes");
        assert_eq!(identity.name, "obs-overlay");
        assert_eq!(identity.scopes, scopes);
    }

    #[test]
    fn empty_token_never_authorizes() {
        let registry = TokenRegistry::new();
        registry.register("obs-overlay", Scope::all());
        assert_eq!(registry.authorize_token(""), None);
    }

    #[test]
    fn re_minting_invalidates_the_previous_token() {
        let registry = TokenRegistry::new();
        registry.register("obs-overlay", Scope::all());
        let first = registry.mint("obs-overlay").unwrap();
        let second = registry.mint("obs-overlay").unwrap();

        assert_ne!(first, second);
        assert_eq!(registry.authorize_token(&first), None);
        assert!(registry.authorize_token(&second).is_some());
    }

    #[test]
    fn revoke_kills_the_current_token_but_keeps_the_name_registered() {
        let registry = TokenRegistry::new();
        registry.register("obs-overlay", Scope::all());
        let token = registry.mint("obs-overlay").unwrap();

        registry.revoke("obs-overlay");
        assert_eq!(registry.authorize_token(&token), None);
        assert!(registry.identity_for_name("obs-overlay").is_some());

        let fresh = registry.mint("obs-overlay").expect("still registered");
        assert!(registry.authorize_token(&fresh).is_some());
    }

    #[test]
    fn identity_for_name_needs_no_token_but_still_needs_registration() {
        let registry = TokenRegistry::new();
        assert_eq!(registry.identity_for_name("unknown"), None);

        registry.register("discord-bot", HashSet::from([Scope::Status]));
        let identity = registry
            .identity_for_name("discord-bot")
            .expect("registered name resolves");
        assert_eq!(identity.scopes, HashSet::from([Scope::Status]));
    }

    #[test]
    fn two_names_get_independent_scope_grants() {
        let registry = TokenRegistry::new();
        registry.register("obs-overlay", HashSet::from([Scope::BrowserSourceRead]));
        registry.register(
            "music-panel",
            HashSet::from([Scope::MusicRead, Scope::MusicWrite]),
        );

        let obs = registry.identity_for_name("obs-overlay").unwrap();
        assert!(!obs.scopes.contains(&Scope::MusicWrite));

        let music = registry.identity_for_name("music-panel").unwrap();
        assert!(music.scopes.contains(&Scope::MusicWrite));
    }
}
