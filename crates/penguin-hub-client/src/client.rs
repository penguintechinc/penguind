//! The sync state machine: enroll, token upkeep, conditional sync, verify,
//! clamp, apply, report. One [`HubClient::sync_once`] call is one poll.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tracing::Instrument;
use url::Url;

use penguin_wasm_host::distribution::{
    FetchError, HubFetcher, HubMethod, HubRequest, HubResponse, MAX_HUB_JSON_BYTES, ModuleManifest,
};

use crate::cache::{CacheLoad, CachedState, HubCache};
use crate::clamp::{
    ClampedLicense, EffectiveLimits, LocalCeiling, clamp_max_stale, clamp_policy,
    clamp_poll_interval,
};
use crate::creds::{CredentialStore, Credentials};
use crate::error::HubError;
use crate::metrics::HubMetrics;
use crate::model::{
    EnrollRequest, Envelope, ManifestWire, ModuleStatus, Problem, RefreshRequest, StatusReport,
    SyncBundle, TokenResponse, error_code,
};
use crate::sink::{DesiredModule, ModuleSink};

/// Access tokens this close to expiry are refreshed before use.
const TOKEN_SKEW_S: i64 = 60;

/// Static, locally-sourced configuration. Nothing here comes from the hub.
pub struct HubClientConfig {
    /// Hub base URL (https, normalised to end with `/`).
    pub hub_url: Url,
    /// 1 linux, 2 macos, 3 windows.
    pub platform: u8,
    /// Agent semver, sent on enroll and in status reports.
    pub agent_version: String,
    /// What any hub policy is clamped against.
    pub ceiling: LocalCeiling,
    /// One-time enrollment secret (from env, never from the hub).
    pub bootstrap_token: Option<String>,
    /// Poll interval before the first bundle arrives.
    pub default_poll_s: u64,
    /// Longest `Retry-After` the agent will honour.
    pub max_retry_after: Duration,
}

impl HubClientConfig {
    /// Validates `hub_url` (https, no embedded credentials) and fills defaults.
    pub fn new(
        hub_url: &str,
        platform: u8,
        agent_version: &str,
        ceiling: LocalCeiling,
    ) -> Result<Self, HubError> {
        let mut url = Url::parse(hub_url).map_err(|e| HubError::Config(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(HubError::Config("hub url must be https".into()));
        }
        if !url.username().is_empty() || url.password().is_some() || url.host().is_none() {
            return Err(HubError::Config(
                "hub url must be host-only, no credentials".into(),
            ));
        }
        if !url.path().ends_with('/') {
            let p = format!("{}/", url.path());
            url.set_path(&p);
        }
        Ok(Self {
            hub_url: url,
            platform,
            agent_version: agent_version.to_string(),
            ceiling,
            bootstrap_token: None,
            default_poll_s: 300,
            max_retry_after: Duration::from_secs(3600),
        })
    }
}

/// What one poll did; the runner turns this into the next delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// 304: nothing changed.
    NotModified,
    /// A bundle was applied; payload is the `ApplyResult` (1 applied, 2 partial, 3 rejected).
    Applied(u8),
    /// 410: the agent is revoked; stop syncing.
    Revoked,
    /// The hub asked us to wait (429 / 5xx with `Retry-After`).
    RetryAfter(Duration),
    /// Transient failure; keep cached state and back off.
    Backoff,
    /// Not enrolled and no bootstrap token to enroll with.
    NoCredentials,
}

/// How the cache was used at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStatus {
    /// No cache: license defaults, no hub modules.
    Fresh,
    /// Cache restored; this many modules re-verified and loaded.
    Restored(usize),
    /// Cache older than `max_stale_s`: nothing loaded.
    Stale,
    /// Cache unreadable: everything denied until the hub answers.
    DenyAll,
}

/// Why a usable access token could not be produced.
enum TokenFail {
    NoCredentials,
    Revoked,
    Rejected,
    Transient(Option<Duration>),
}

/// A module that is loaded now.
struct Applied {
    version: String,
    sha256: String,
    limits: EffectiveLimits,
}

struct State {
    etag: Option<String>,
    applied: BTreeMap<String, Applied>,
    highest: BTreeMap<String, String>,
    creds: Option<Credentials>,
    bootstrap: Option<String>,
    last_contact: Option<i64>,
    started_at: i64,
    poll_s: u64,
    max_stale_s: u64,
    stale: bool,
    revoked: bool,
}

/// A read-only view for the daemon/CLI and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// ETag of the fully applied bundle.
    pub etag: Option<String>,
    /// Loaded `(id, version)` pairs.
    pub applied: Vec<(String, String)>,
    /// Whether the last contact is older than the staleness bound.
    pub stale: bool,
    /// Whether the hub revoked this agent.
    pub revoked: bool,
    /// Current poll interval in seconds.
    pub poll_s: u64,
}

/// The hub client. Cheap to share behind an `Arc`; polls are serialised.
pub struct HubClient {
    cfg: HubClientConfig,
    fetcher: HubFetcher,
    creds: CredentialStore,
    cache: HubCache,
    sink: Arc<dyn ModuleSink>,
    license: Arc<ClampedLicense>,
    metrics: HubMetrics,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    state: Mutex<State>,
}

/// Unix seconds now, clamped to 0 before the epoch.
/// Raises each mark in `into` to the max of itself and `from` (semver);
/// an unparsable incoming mark never replaces a parsable one.
fn merge_high_water(into: &mut BTreeMap<String, String>, from: &BTreeMap<String, String>) {
    for (id, v) in from {
        let higher = match (into.get(id).map(|c| Version::parse(c)), Version::parse(v)) {
            (None, _) => true,
            (Some(Ok(cur)), Ok(new)) => new > cur,
            (Some(Err(_)), Ok(_)) => true,
            (Some(_), Err(_)) => false,
        };
        if higher {
            into.insert(id.clone(), v.clone());
        }
    }
}

fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Metric label for an HTTP status.
fn status_label(status: u16) -> &'static str {
    match status {
        200 => "200",
        304 => "304",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

/// Parses a success envelope's `data`; an error envelope becomes a protocol error.
fn parse_data<T: DeserializeOwned>(body: &[u8]) -> Result<T, HubError> {
    let env: Envelope<T> =
        serde_json::from_slice(body).map_err(|e| HubError::Protocol(e.to_string()))?;
    if env.status != "success" {
        return Err(HubError::Protocol(format!(
            "envelope status `{}`",
            env.status
        )));
    }
    Ok(env.data)
}

/// Best-effort problem title for logging a non-success reply.
fn problem_title(body: &[u8]) -> String {
    serde_json::from_slice::<Envelope<Problem>>(body)
        .map(|e| e.data.title)
        .unwrap_or_default()
}

/// Converts a wire manifest to the host's manifest type.
fn to_manifest(m: &ManifestWire) -> ModuleManifest {
    ModuleManifest {
        id: m.id.clone(),
        version: m.version.clone(),
        sha256: m.sha256.clone(),
        signature: m.signature.clone(),
        binary_url: m.binary_url.clone(),
    }
}

impl HubClient {
    /// Builds a client; nothing touches the network or disk until
    /// [`start`](Self::start) / [`sync_once`](Self::sync_once).
    pub fn new(
        cfg: HubClientConfig,
        fetcher: HubFetcher,
        creds: CredentialStore,
        cache: HubCache,
        sink: Arc<dyn ModuleSink>,
        license: Arc<ClampedLicense>,
        metrics: HubMetrics,
    ) -> Self {
        metrics.set_token_store(creds.kind());
        let now = system_now();
        let state = State {
            etag: None,
            applied: BTreeMap::new(),
            highest: BTreeMap::new(),
            creds: None,
            bootstrap: cfg.bootstrap_token.clone(),
            last_contact: None,
            started_at: now,
            poll_s: clamp_poll_interval(cfg.default_poll_s),
            max_stale_s: cfg.ceiling.max_stale_s,
            stale: false,
            revoked: false,
        };
        Self {
            cfg,
            fetcher,
            creds,
            cache,
            sink,
            license,
            metrics,
            clock: Arc::new(system_now),
            state: Mutex::new(state),
        }
    }

    /// Replaces the clock (tests drive staleness and token expiry with it).
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Current poll interval.
    pub async fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.state.lock().await.poll_s)
    }

    /// A read-only view of the current state.
    pub async fn snapshot(&self) -> Snapshot {
        let st = self.state.lock().await;
        Snapshot {
            etag: st.etag.clone(),
            applied: st
                .applied
                .iter()
                .map(|(k, v)| (k.clone(), v.version.clone()))
                .collect(),
            stale: st.stale,
            revoked: st.revoked,
            poll_s: st.poll_s,
        }
    }

    /// Restores the offline cache: every module is re-verified against the
    /// locally pinned keys before it is loaded; a corrupt state file puts the
    /// agent in deny-all until the hub answers.
    pub async fn start(&self) -> StartStatus {
        let mut st = self.state.lock().await;
        match self.cache.load_high_water() {
            Ok(marks) => merge_high_water(&mut st.highest, &marks),
            Err(e) => tracing::warn!(error = %e, "rollback high-water file unreadable"),
        }
        let loaded = match self.cache.load() {
            CacheLoad::Missing => return StartStatus::Fresh,
            CacheLoad::Corrupt(reason) => {
                tracing::warn!(%reason, "hub cache corrupt; deny-all until the hub answers");
                self.license.set_deny_all(true);
                return StartStatus::DenyAll;
            }
            CacheLoad::Loaded(s) => *s,
        };
        let bundle = &loaded.bundle;
        st.last_contact = Some(loaded.last_contact);
        st.poll_s = clamp_poll_interval(bundle.poll_interval_s);
        st.max_stale_s = clamp_max_stale(&self.cfg.ceiling, bundle.max_stale_s);
        merge_high_water(&mut st.highest, &loaded.highest);
        self.license.set_hub_flags(bundle.flags.clone());
        let age = self.now().saturating_sub(loaded.last_contact);
        if age > i64::try_from(st.max_stale_s).unwrap_or(i64::MAX) {
            st.stale = true;
            tracing::warn!(
                age_s = age,
                "hub cache older than max_stale_s; no hub modules loaded"
            );
            self.update_gauges(&st);
            return StartStatus::Stale;
        }
        let eff = clamp_policy(&self.cfg.ceiling, &bundle.policy);
        let mut all_ok = true;
        for m in &bundle.modules {
            let ok = match self.cached_verified(m) {
                Some(v) => self.load_into_sink(&mut st, m, v, &eff).await.is_ok(),
                None => false,
            };
            all_ok &= ok;
        }
        st.etag = (all_ok && !loaded.etag.is_empty()).then(|| loaded.etag.clone());
        self.update_gauges(&st);
        StartStatus::Restored(st.applied.len())
    }

    /// Unloads hub-delivered modules if the last contact is older than the
    /// staleness bound (restrictive fallback). Returns whether it is stale.
    pub async fn check_staleness(&self) -> bool {
        let mut st = self.state.lock().await;
        let Some(last) = st.last_contact else {
            self.update_gauges(&st);
            return false;
        };
        let age = self.now().saturating_sub(last);
        let stale = age > i64::try_from(st.max_stale_s).unwrap_or(i64::MAX);
        if stale && !st.stale {
            tracing::warn!(age_s = age, "hub stale: unloading hub-delivered modules");
            let ids: Vec<String> = st.applied.keys().cloned().collect();
            for id in ids {
                self.sink.unload(&id).await;
                st.applied.remove(&id);
            }
            // Force a full apply when the hub returns, even if its ETag is unchanged.
            st.etag = None;
        }
        st.stale = stale;
        self.update_gauges(&st);
        stale
    }

    /// Performs one poll.
    pub async fn sync_once(&self) -> SyncOutcome {
        let span = tracing::info_span!("hub.sync", result = tracing::field::Empty);
        let rec = span.clone();
        async {
            let mut st = self.state.lock().await;
            let out = self.sync_locked(&mut st).await;
            self.update_gauges(&st);
            rec.record("result", format!("{out:?}").as_str());
            out
        }
        .instrument(span)
        .await
    }

    fn update_gauges(&self, st: &State) {
        let since = st.last_contact.unwrap_or(st.started_at);
        self.metrics
            .set_staleness(self.now().saturating_sub(since).max(0) as f64);
        self.metrics.set_modules(st.applied.len());
    }

    fn url(&self, path: &str) -> Result<String, HubError> {
        self.cfg
            .hub_url
            .join(path)
            .map(|u| u.to_string())
            .map_err(|e| HubError::Config(e.to_string()))
    }

    async fn call(
        &self,
        method: HubMethod,
        path: &str,
        bearer: Option<&str>,
        inm: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<HubResponse, FetchError> {
        let url = self
            .url(path)
            .map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
        self.fetcher
            .send(HubRequest {
                method,
                url: &url,
                bearer,
                if_none_match: inm,
                json_body: body,
                max_response: MAX_HUB_JSON_BYTES,
            })
            .await
    }

    fn clamp_retry(&self, d: Option<Duration>) -> Option<Duration> {
        d.map(|d| d.clamp(Duration::from_secs(1), self.cfg.max_retry_after))
    }

    async fn sync_locked(&self, st: &mut State) -> SyncOutcome {
        if st.revoked {
            return SyncOutcome::Revoked;
        }
        let mut force_refresh = false;
        for attempt in 0..2 {
            let token = match self.access_token(st, force_refresh).await {
                Ok(t) => t,
                Err(TokenFail::NoCredentials) => return SyncOutcome::NoCredentials,
                Err(TokenFail::Revoked) => return self.revoke(st).await,
                Err(TokenFail::Rejected) => return SyncOutcome::Backoff,
                Err(TokenFail::Transient(d)) => {
                    return self
                        .clamp_retry(d)
                        .map_or(SyncOutcome::Backoff, SyncOutcome::RetryAfter);
                }
            };
            let t0 = Instant::now();
            let resp = self
                .call(
                    HubMethod::Get,
                    "api/v1/agent/sync",
                    Some(&token),
                    st.etag.as_deref(),
                    None,
                )
                .await;
            let elapsed = t0.elapsed().as_secs_f64();
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    self.metrics.record_request("error", elapsed);
                    tracing::warn!(error = %e, "hub sync request failed");
                    return SyncOutcome::Backoff;
                }
            };
            self.metrics
                .record_request(status_label(resp.status), elapsed);
            match resp.status {
                304 => {
                    st.last_contact = Some(self.now());
                    st.stale = false;
                    self.persist(st);
                    return SyncOutcome::NotModified;
                }
                200 => return self.apply_200(st, resp, &token).await,
                401 if attempt == 0 => force_refresh = true,
                401 => return SyncOutcome::Backoff,
                410 => return self.revoke(st).await,
                _ => {
                    tracing::warn!(
                        status = resp.status,
                        title = %problem_title(&resp.body),
                        "hub sync refused"
                    );
                    let wait =
                        if resp.status == 429 || resp.status >= 500 {
                            self.clamp_retry(resp.retry_after.or_else(|| {
                                (resp.status == 429).then_some(Duration::from_secs(60))
                            }))
                        } else {
                            None
                        };
                    return wait.map_or(SyncOutcome::Backoff, SyncOutcome::RetryAfter);
                }
            }
        }
        SyncOutcome::Backoff
    }

    /// Returns a non-expiring access token, enrolling or refreshing as needed.
    async fn access_token(&self, st: &mut State, force: bool) -> Result<String, TokenFail> {
        if st.creds.is_none() {
            st.creds = self.creds.load().await.map_err(|e| {
                tracing::warn!(error = %e, "credential store unavailable");
                TokenFail::Transient(None)
            })?;
        }
        let Some(c) = st.creds.clone() else {
            return self.enroll(st).await;
        };
        if force || c.access_expires_at - self.now() <= TOKEN_SKEW_S {
            return self.refresh(st, &c).await;
        }
        Ok(c.access_token)
    }

    /// Exchanges the one-time bootstrap token for an access/refresh pair.
    async fn enroll(&self, st: &mut State) -> Result<String, TokenFail> {
        let Some(bootstrap) = st.bootstrap.clone() else {
            return Err(TokenFail::NoCredentials);
        };
        let body = serde_json::to_vec(&EnrollRequest {
            platform: self.cfg.platform,
            agent_version: &self.cfg.agent_version,
        })
        .map_err(|_| TokenFail::Transient(None))?;
        let resp = self
            .call(
                HubMethod::Post,
                "api/v1/agent/enroll",
                Some(&bootstrap),
                None,
                Some(body),
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "enroll request failed");
                TokenFail::Transient(None)
            })?;
        match resp.status {
            200 | 201 => {
                st.bootstrap = None; // consumed by the hub
                self.accept_tokens(st, &resp.body).await
            }
            400 | 401 | 403 => {
                tracing::warn!("bootstrap token rejected by hub");
                st.bootstrap = None;
                Err(TokenFail::Rejected)
            }
            410 => Err(TokenFail::Revoked),
            _ => Err(TokenFail::Transient(resp.retry_after)),
        }
    }

    /// Rotates the refresh token. A rejected refresh token means the chain is
    /// dead: credentials are wiped and the agent must re-enroll.
    async fn refresh(&self, st: &mut State, c: &Credentials) -> Result<String, TokenFail> {
        let body = serde_json::to_vec(&RefreshRequest {
            refresh_token: &c.refresh_token,
        })
        .map_err(|_| TokenFail::Transient(None))?;
        let resp = self
            .call(
                HubMethod::Post,
                "api/v1/agent/token",
                None,
                None,
                Some(body),
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "token refresh request failed");
                TokenFail::Transient(None)
            })?;
        match resp.status {
            200 | 201 => self.accept_tokens(st, &resp.body).await,
            400 | 401 => {
                tracing::warn!("refresh token rejected; re-enrollment required");
                st.creds = None;
                if let Err(e) = self.creds.clear().await {
                    tracing::warn!(error = %e, "could not clear stored credentials");
                }
                Err(TokenFail::Rejected)
            }
            410 => Err(TokenFail::Revoked),
            _ => Err(TokenFail::Transient(resp.retry_after)),
        }
    }

    /// Parses a `TokenResponse`, persists it (secret store only) and returns the access token.
    async fn accept_tokens(&self, st: &mut State, body: &[u8]) -> Result<String, TokenFail> {
        let t: TokenResponse = parse_data(body).map_err(|e| {
            tracing::warn!(error = %e, "bad token response");
            TokenFail::Transient(None)
        })?;
        let creds = Credentials {
            agent_id: t.agent_id,
            access_token: t.access_token.clone(),
            access_expires_at: self
                .now()
                .saturating_add(i64::try_from(t.expires_in).unwrap_or(0)),
            refresh_token: t.refresh_token,
        };
        // The refresh token rotated server-side; if it cannot be stored the
        // agent re-enrolls after a restart, which is loud but safe.
        if let Err(e) = self.creds.save(&creds).await {
            tracing::error!(error = %e, "could not persist rotated credentials");
        }
        st.creds = Some(creds);
        Ok(t.access_token)
    }

    async fn apply_200(&self, st: &mut State, resp: HubResponse, token: &str) -> SyncOutcome {
        let bundle: SyncBundle = match parse_data(&resp.body) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "bad sync bundle");
                return SyncOutcome::Backoff;
            }
        };
        let etag = resp.etag.unwrap_or_default();
        self.apply_bundle(st, bundle, etag, token).await
    }

    /// Verifies, clamps and applies a bundle, unloads dropped modules,
    /// persists the cache, then reports status (best effort).
    async fn apply_bundle(
        &self,
        st: &mut State,
        bundle: SyncBundle,
        etag: String,
        token: &str,
    ) -> SyncOutcome {
        self.license.set_deny_all(false);
        self.license.set_hub_flags(bundle.flags.clone());
        let eff = clamp_policy(&self.cfg.ceiling, &bundle.policy);
        st.poll_s = clamp_poll_interval(bundle.poll_interval_s);
        st.max_stale_s = clamp_max_stale(&self.cfg.ceiling, bundle.max_stale_s);

        let mut statuses: Vec<ModuleStatus> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for m in &bundle.modules {
            let res = if seen.insert(m.id.clone()) {
                self.apply_module(st, m, &eff, token).await
            } else {
                Err(error_code::DUPLICATE)
            };
            statuses.push(ModuleStatus {
                id: m.id.clone(),
                version: m.version.clone(),
                loaded: res.is_ok(),
                error_code: res.err(),
            });
        }
        let dropped: Vec<String> = st
            .applied
            .keys()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for id in dropped {
            if st.applied.remove(&id).is_some() {
                self.sink.unload(&id).await;
                tracing::info!(module = %id, "module dropped by hub; unloaded");
            }
            // The rollback high-water mark is kept: a later re-offer of an
            // older version must still be refused.
        }

        let total = statuses.len();
        let ok = statuses.iter().filter(|s| s.loaded).count();
        let result: u8 = if ok == total {
            1
        } else if ok > 0 {
            2
        } else {
            3
        };
        st.last_contact = Some(self.now());
        st.stale = false;
        // Only a fully applied bundle may short-circuit the next poll with a 304.
        st.etag = (result == 1 && !etag.is_empty()).then(|| etag.clone());
        self.persist_with(st, &bundle);
        let keep: Vec<String> = st.applied.values().map(|a| a.sha256.clone()).collect();
        self.cache.gc_blobs(&keep);

        let report = StatusReport {
            applied_etag: etag,
            result,
            agent_version: self.cfg.agent_version.clone(),
            modules: statuses,
        };
        if self.report(&report, token).await == Some(410) {
            return self.revoke(st).await;
        }
        SyncOutcome::Applied(result)
    }

    /// Verifies (cache first, then hub download) and loads one module.
    /// `Err` carries the `error_code` reported to the hub.
    async fn apply_module(
        &self,
        st: &mut State,
        m: &ManifestWire,
        eff: &EffectiveLimits,
        token: &str,
    ) -> Result<(), i64> {
        let Ok(version) = Version::parse(&m.version) else {
            self.metrics.record_verify(false);
            return Err(error_code::VERIFY);
        };
        if let Some(h) = st.highest.get(&m.id).and_then(|h| Version::parse(h).ok())
            && version < h
        {
            tracing::warn!(module = %m.id, version = %m.version, highest = %h, "rollback refused");
            return Err(error_code::ROLLBACK);
        }
        if st
            .applied
            .get(&m.id)
            .is_some_and(|a| a.version == m.version && a.sha256 == m.sha256 && a.limits == *eff)
        {
            return Ok(());
        }
        let verified = match self.cached_verified(m) {
            Some(v) => v,
            None => {
                match self
                    .fetcher
                    .fetch_module(&to_manifest(m), Some(token))
                    .await
                {
                    Ok(v) => {
                        self.metrics.record_verify(true);
                        if let Err(e) = self.cache.store_blob(v.sha256(), v.as_bytes()) {
                            tracing::warn!(error = %e, "could not cache module binary");
                        }
                        v
                    }
                    Err(FetchError::Verification(e)) => {
                        self.metrics.record_verify(false);
                        tracing::warn!(module = %m.id, error = %e, "module verification failed");
                        return Err(error_code::VERIFY);
                    }
                    Err(e) => {
                        tracing::warn!(module = %m.id, error = %e, "module fetch failed");
                        return Err(error_code::FETCH);
                    }
                }
            }
        };
        let keep_higher = st
            .highest
            .get(&m.id)
            .and_then(|h| Version::parse(h).ok())
            .is_some_and(|h| h > version);
        if !keep_higher {
            st.highest.insert(m.id.clone(), m.version.clone());
        }
        self.load_into_sink(st, m, verified, eff).await
    }

    /// Re-verifies a cached binary against the pinned keys (cache is not trusted).
    fn cached_verified(
        &self,
        m: &ManifestWire,
    ) -> Option<penguin_wasm_host::distribution::VerifiedModule> {
        let bytes = self.cache.read_blob(
            &m.sha256.to_ascii_lowercase(),
            self.cfg.ceiling.max_wasm_bytes,
        )?;
        match self.fetcher.verify_with_any_key(&to_manifest(m), bytes) {
            Ok(v) => {
                self.metrics.record_verify(true);
                Some(v)
            }
            Err(e) => {
                self.metrics.record_verify(false);
                tracing::warn!(module = %m.id, error = %e, "cached module failed re-verification");
                None
            }
        }
    }

    async fn load_into_sink(
        &self,
        st: &mut State,
        m: &ManifestWire,
        verified: penguin_wasm_host::distribution::VerifiedModule,
        eff: &EffectiveLimits,
    ) -> Result<(), i64> {
        let sha = verified.sha256().to_string();
        let desired = DesiredModule {
            id: m.id.clone(),
            version: m.version.clone(),
            module: Arc::new(verified),
            limits: eff.to_module_limits(),
        };
        match self.sink.load(desired).await {
            Ok(()) => {
                st.applied.insert(
                    m.id.clone(),
                    Applied {
                        version: m.version.clone(),
                        sha256: sha,
                        limits: eff.clone(),
                    },
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(module = %m.id, code = e.code, reason = %e.reason, "module load refused");
                Err(e.code)
            }
        }
    }

    /// Best-effort status POST; returns the HTTP status if one came back.
    async fn report(&self, report: &StatusReport, token: &str) -> Option<u16> {
        let body = serde_json::to_vec(report).ok()?;
        match self
            .call(
                HubMethod::Post,
                "api/v1/agent/status",
                Some(token),
                None,
                Some(body),
            )
            .await
        {
            Ok(r) => {
                if r.status != 204 && r.status != 200 {
                    tracing::warn!(status = r.status, "status report not accepted");
                }
                Some(r.status)
            }
            Err(e) => {
                tracing::warn!(error = %e, "status report failed (best effort)");
                None
            }
        }
    }

    /// Writes the cache from the current state when a bundle is known.
    fn persist(&self, st: &State) {
        if let CacheLoad::Loaded(mut s) = self.cache.load() {
            s.last_contact = st.last_contact.unwrap_or(s.last_contact);
            if let Err(e) = self.cache.save(&s) {
                tracing::warn!(error = %e, "could not refresh hub cache");
            }
        }
    }

    /// Writes the cache for `bundle` and the current state.
    fn persist_with(&self, st: &State, bundle: &SyncBundle) {
        let state = CachedState {
            etag: st.etag.clone().unwrap_or_default(),
            bundle: bundle.clone(),
            last_contact: st.last_contact.unwrap_or_else(|| self.now()),
            highest: st.highest.clone(),
        };
        if let Err(e) = self.cache.save(&state) {
            tracing::warn!(error = %e, "could not write hub cache");
        }
        self.persist_high_water(st);
    }

    /// Writes the monotonic rollback high-water marks.
    fn persist_high_water(&self, st: &State) {
        if let Err(e) = self.cache.save_high_water(&st.highest) {
            tracing::warn!(error = %e, "could not write rollback high-water marks");
        }
    }

    /// Explicit local operator action: forget the rollback high-water mark
    /// for `id` (or all marks for `None`) so an older version may load again.
    /// The hub can never trigger this.
    pub async fn reset_high_water(&self, id: Option<&str>) -> Result<(), HubError> {
        let mut st = self.state.lock().await;
        self.cache.reset_high_water(id)?;
        match id {
            Some(id) => {
                st.highest.remove(id);
            }
            None => st.highest.clear(),
        }
        tracing::warn!(module = ?id, "rollback high-water reset by local operator");
        Ok(())
    }

    /// 410: unload everything the hub delivered and wipe credentials + cache.
    async fn revoke(&self, st: &mut State) -> SyncOutcome {
        tracing::warn!("agent revoked by hub: unloading modules, wiping credentials");
        st.revoked = true;
        let ids: Vec<String> = st.applied.keys().cloned().collect();
        for id in ids {
            self.sink.unload(&id).await;
        }
        st.applied.clear();
        // Revocation never lowers the rollback high-water marks.
        st.etag = None;
        st.creds = None;
        st.bootstrap = None;
        if let Err(e) = self.creds.clear().await {
            tracing::warn!(error = %e, "could not clear stored credentials");
        }
        self.cache.clear();
        self.persist_high_water(st);
        self.license.set_hub_flags(BTreeMap::new());
        SyncOutcome::Revoked
    }
}
