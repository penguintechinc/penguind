//! [`BridgeState`]: the one piece of state both transports
//! ([`crate::bridge::http`] and [`crate::bridge::unixsock`]) share — the
//! token registry, the module handle relayed calls run through, and the
//! event-push channel a future [`crate::bridge::BridgeAdapter`] publishes
//! into. The transport modules are thin front doors; this is the room
//! behind them.

use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::bridge::relay::{self, RelayError};
use crate::bridge::scope::Operation;
use crate::bridge::token::{ScriptIdentity, TokenRegistry};
use crate::module::WaddlesGatewayModule;

/// How many not-yet-delivered events a slow WebSocket subscriber can fall
/// behind by before the oldest are dropped. Generous for a local,
/// low-volume integration channel; a lagging receiver sees
/// [`broadcast::error::RecvError::Lagged`] rather than this bridge ever
/// blocking a publisher on a stalled subscriber.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// One event the bridge pushes to every currently-connected WebSocket
/// client. `kind` is a short, stable tag (`"announcement.published"`, a
/// future adapter's own event names, ...); `data` is that event's payload.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeEvent {
    pub kind: String,
    pub data: Value,
}

/// Shared bridge core: one instance per running bridge, held behind an
/// `Arc` so both transports (and any future [`crate::bridge::BridgeAdapter`])
/// can hold a cheap handle to it.
pub struct BridgeState {
    module: WaddlesGatewayModule,
    /// The module's live Community Access Token, kept only so
    /// [`relay::relay`] can scrub it out of a relayed response/error — never
    /// sent to, or accepted from, a connecting script. See `bridge`'s
    /// module doc for the security model this exists to uphold.
    cat: String,
    pub tokens: TokenRegistry,
    events: broadcast::Sender<BridgeEvent>,
}

impl BridgeState {
    /// Builds a fresh bridge core wrapping `module`'s hub connection, with
    /// no integrations registered yet — [`crate::bridge::start`] registers
    /// each `bridge.allowed_integrations` name right after this.
    pub fn new(module: WaddlesGatewayModule, cat: String) -> BridgeState {
        let (events, _receiver) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        BridgeState {
            module,
            cat,
            tokens: TokenRegistry::new(),
            events,
        }
    }

    /// Relays `op` to the hub on behalf of `identity`, first checking
    /// `identity` actually holds `op`'s required scope. Fail-closed: a
    /// missing grant never reaches [`relay::relay`] at all. Every denial or
    /// failure is logged through the module's own logger — using the
    /// already-scrubbed [`RelayError`] message, never a raw hub error —
    /// so an operator can see why a script's call was refused.
    pub async fn relay(
        &self,
        identity: &ScriptIdentity,
        op: Operation,
        params: &Value,
    ) -> Result<Value, ScopedRelayError> {
        if !identity.scopes.contains(&op.required_scope()) {
            self.module.host().logger().warn(
                "waddles-gateway bridge: relay denied — integration lacks the required scope",
                &[("integration", &identity.name), ("op", &format!("{op:?}"))],
            );
            return Err(ScopedRelayError::OutOfScope);
        }
        match relay::relay(&self.module, &self.cat, op, params).await {
            Ok(value) => Ok(value),
            Err(err) => {
                self.module.host().logger().warn(
                    "waddles-gateway bridge: relay failed",
                    &[("integration", &identity.name), ("error", &err.to_string())],
                );
                Err(ScopedRelayError::Relay(err))
            }
        }
    }

    /// A new subscription to the event-push channel — one per connected
    /// WebSocket client.
    pub fn subscribe(&self) -> broadcast::Receiver<BridgeEvent> {
        self.events.subscribe()
    }

    /// How many subscribers are currently attached — tests use this to
    /// wait for a WebSocket client to finish subscribing before publishing,
    /// since a publish with zero subscribers reaches no one (see
    /// [`BridgeState::publish_event`]). Also a natural future building
    /// block for a bridge health/status surface.
    #[allow(dead_code)]
    pub fn subscriber_count(&self) -> usize {
        self.events.receiver_count()
    }

    /// Publishes `event` to every current subscriber. A publish with no
    /// subscribers connected is not an error — there is simply no one to
    /// deliver to yet.
    pub fn publish_event(&self, event: BridgeEvent) {
        let _ = self.events.send(event);
    }
}

/// [`BridgeState::relay`]'s error: either the scope check itself failed, or
/// it passed and the relay call underneath failed.
#[derive(Debug, thiserror::Error)]
pub enum ScopedRelayError {
    #[error("integration is not permitted to invoke this operation")]
    OutOfScope,
    #[error(transparent)]
    Relay(#[from] RelayError),
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::bridge::scope::Scope;
    use crate::testutil::{FakeHost, MockHub, MockResponse};
    use penguin_sdk::Module;
    use std::sync::Arc;

    async fn state_against(hub: &MockHub) -> BridgeState {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(dir.path().to_path_buf());
        host.config = serde_json::to_vec(&serde_json::json!({
            "hub": {"base_url": hub.base_url},
            "community_id": "11111111-1111-4111-8111-111111111111",
        }))
        .unwrap();
        let module = WaddlesGatewayModule::new();
        module.init(Arc::new(host)).await.expect("init succeeds");
        BridgeState::new(module, "wdl_c_livesecret".to_string())
    }

    #[tokio::test]
    async fn relay_denies_an_identity_missing_the_required_scope() {
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;
        let identity = ScriptIdentity {
            name: "obs-overlay".to_string(),
            scopes: HashSet::from([Scope::BrowserSourceRead]),
        };

        let err = state
            .relay(&identity, Operation::GetMusicSettings, &Value::Null)
            .await
            .unwrap_err();
        assert!(matches!(err, ScopedRelayError::OutOfScope));

        hub.stop().await;
    }

    #[tokio::test]
    async fn relay_allows_an_identity_with_the_required_scope() {
        let hub = MockHub::start().await;
        hub.respond(
            "GET",
            "/admin/11111111-1111-4111-8111-111111111111/browser-sources",
            MockResponse::json(200, r#"{"success":true,"sources":[]}"#),
        )
        .await;
        let state = state_against(&hub).await;
        let identity = ScriptIdentity {
            name: "obs-overlay".to_string(),
            scopes: HashSet::from([Scope::BrowserSourceRead]),
        };

        let result = state
            .relay(&identity, Operation::ListBrowserSources, &Value::Null)
            .await
            .expect("in-scope relay succeeds");
        assert_eq!(result["sources"].as_array().unwrap().len(), 0);

        hub.stop().await;
    }

    #[tokio::test]
    async fn publish_then_subscribe_can_still_miss_earlier_events() {
        // Documents broadcast-channel semantics this bridge relies on:
        // subscribing is what starts receiving, not registering interest
        // retroactively.
        let hub = MockHub::start().await;
        let state = state_against(&hub).await;
        state.publish_event(BridgeEvent {
            kind: "before-subscribe".to_string(),
            data: Value::Null,
        });

        let mut rx = state.subscribe();
        state.publish_event(BridgeEvent {
            kind: "after-subscribe".to_string(),
            data: Value::Null,
        });

        let received = rx.recv().await.expect("receives the post-subscribe event");
        assert_eq!(received.kind, "after-subscribe");

        hub.stop().await;
    }
}
