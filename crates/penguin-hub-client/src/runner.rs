//! The poll loop: first poll immediately, then every interval ±10% jitter (docs/hub-protocol.md),
//! honouring `Retry-After` and backing off exponentially on failure.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::client::{HubClient, SyncOutcome};

/// Jitter fraction applied around the poll interval.
pub const JITTER: f64 = 0.10;
/// First failure back-off step.
const BACKOFF_BASE: Duration = Duration::from_secs(30);

/// `base` scaled by `1 ± JITTER`; `unit` in `[0,1)` selects the point in the band.
fn jittered(base: Duration, unit: f64) -> Duration {
    let factor = 1.0 + JITTER * (2.0 * unit.clamp(0.0, 1.0) - 1.0);
    Duration::from_secs_f64(base.as_secs_f64() * factor)
}

/// The delay before the next poll, or `None` to stop (revoked). `failures` is
/// the number of consecutive failed polls so far; `unit` is a uniform random
/// number in `[0,1)` (injected so the schedule is testable).
pub fn compute_delay(
    outcome: SyncOutcome,
    interval: Duration,
    failures: u32,
    unit: f64,
) -> Option<Duration> {
    match outcome {
        SyncOutcome::Revoked => None,
        SyncOutcome::NotModified | SyncOutcome::Applied(_) => Some(jittered(interval, unit)),
        // Never earlier than the server asked; jitter only adds.
        SyncOutcome::RetryAfter(d) => Some(d + jittered(Duration::from_secs(1), unit)),
        SyncOutcome::Backoff | SyncOutcome::NoCredentials => {
            let exp = BACKOFF_BASE.saturating_mul(1u32 << failures.min(10));
            Some(jittered(exp.min(interval), unit))
        }
    }
}

/// Runs the loop until `cancel` fires or the hub revokes this agent.
pub async fn run_loop(client: Arc<HubClient>, cancel: CancellationToken) {
    let mut failures: u32 = 0;
    loop {
        let outcome = tokio::select! {
            _ = cancel.cancelled() => return,
            o = client.sync_once() => o,
        };
        client.check_staleness().await;
        failures = match outcome {
            SyncOutcome::Backoff | SyncOutcome::NoCredentials => failures.saturating_add(1),
            _ => 0,
        };
        let interval = client.poll_interval().await;
        let Some(delay) = compute_delay(outcome, interval, failures, rand::random::<f64>()) else {
            tracing::warn!("hub sync loop stopped: agent revoked");
            return;
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const I: Duration = Duration::from_secs(300);

    #[test]
    fn jitter_stays_within_ten_percent() {
        for unit in [0.0, 0.25, 0.5, 0.999, 1.0] {
            let d = compute_delay(SyncOutcome::NotModified, I, 0, unit).expect("delay");
            assert!(
                d >= Duration::from_secs(270) && d <= Duration::from_secs(330),
                "{d:?}"
            );
        }
        assert_eq!(
            compute_delay(SyncOutcome::Applied(1), I, 0, 0.5),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn retry_after_is_a_floor() {
        let want = Duration::from_secs(900);
        for unit in [0.0, 0.5, 1.0] {
            let d = compute_delay(SyncOutcome::RetryAfter(want), I, 0, unit).expect("delay");
            assert!(d >= want, "{d:?}");
        }
    }

    #[test]
    fn backoff_grows_and_caps_at_interval() {
        let d1 = compute_delay(SyncOutcome::Backoff, I, 1, 0.5).expect("d");
        let d3 = compute_delay(SyncOutcome::Backoff, I, 3, 0.5).expect("d");
        let d9 = compute_delay(SyncOutcome::NoCredentials, I, 9, 1.0).expect("d");
        assert!(d1 < d3);
        assert!(
            d9 <= Duration::from_secs(360),
            "capped near the interval: {d9:?}"
        );
    }

    #[test]
    fn revoked_stops_the_loop() {
        assert_eq!(compute_delay(SyncOutcome::Revoked, I, 0, 0.5), None);
    }
}
