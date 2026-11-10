//! Host-side tool executors (`logger`, `config_read`, `metrics_publish`,
//! `doh_query`). Only tools with a real backing are implemented;
//! every other declared tool fails loudly as `NotImplemented` rather than
//! returning canned data.

mod config_executor;
mod doh_executor;
mod executor;
mod logger_executor;
mod metrics_executor;

pub use config_executor::ConfigReadExecutor;
pub use doh_executor::{DEFAULT_DOH_ENDPOINT, DohQueryExecutor, MAX_DOH_RESPONSE_BYTES};
pub use executor::ToolExecutor;
pub use logger_executor::{LoggerExecutor, MAX_LOG_MESSAGE_BYTES, sanitize_message};
pub use metrics_executor::{MAX_LABELS, MAX_METRICS, MAX_SERIES, MetricsPublishExecutor};
