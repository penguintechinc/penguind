//! Registry of built-in modules the daemon can load without an external
//! plugin binary.
//!
//! `squawk` was the first entry, proving the M1-M4 plugin framework end to
//! end. `tobogganing` is the second — and, per `docs/PARITY.md`, the last
//! Go-dependent module: once it is registered here, the shipped agent has
//! no Go left in it. `waddlebot` is the third: a CLI-over-API surface over
//! the waddlebot hub (its local integration bridge is a separate, later
//! track — see `penguin_module_waddlebot::WaddlebotModule::start_bridge`).
//! `waddleai` is the fourth: the desktop-side companion to WaddleAI's
//! agent-hooks feature — shim installation, credential storage, and
//! telemetry only, never policy (see
//! `penguin_module_waddleai::WaddleAiModule`'s top-level doc).

use std::collections::BTreeMap;

use penguin_sdk::Factory;

/// Builds the name -> [`Factory`] map for every compiled-in module, for
/// [`penguin_daemon::supervisor::SupervisorConfig::registry`] (see
/// `bins/penguind/src/daemon_main.rs`).
pub fn builtin_modules() -> BTreeMap<String, Factory> {
    let mut registry: BTreeMap<String, Factory> = BTreeMap::new();
    registry.insert("squawk".to_string(), penguin_module_squawk::factory);
    registry.insert(
        "tobogganing".to_string(),
        penguin_module_tobogganing::factory,
    );
    registry.insert(
        "waddles-social".to_string(),
        penguin_module_waddles_social::factory,
    );
    registry.insert(
        "waddles-gateway".to_string(),
        penguin_module_waddles_gateway::factory,
    );
    registry.insert("waddleai".to_string(), penguin_module_waddleai::factory);
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squawk_is_registered_as_a_builtin() {
        let registry = builtin_modules();
        assert!(registry.contains_key("squawk"));
    }

    #[test]
    fn squawk_factory_reports_its_own_identity_before_init() {
        let registry = builtin_modules();
        let factory = registry.get("squawk").expect("squawk registered");
        let info = factory().info();
        assert_eq!(info.name, "squawk");
        assert_eq!(info.version, "1.0.0");
        assert!(
            info.license_feature.is_empty(),
            "squawk is core product and must load with no license gate"
        );
    }

    #[test]
    fn tobogganing_is_registered_as_a_builtin() {
        let registry = builtin_modules();
        assert!(registry.contains_key("tobogganing"));
    }

    #[test]
    fn tobogganing_factory_reports_its_own_identity_before_init() {
        let registry = builtin_modules();
        let factory = registry.get("tobogganing").expect("tobogganing registered");
        let info = factory().info();
        assert_eq!(info.name, "tobogganing");
        assert_eq!(info.version, "1.0.0");
        assert!(
            info.license_feature.is_empty(),
            "tobogganing is core product and must load with no license gate"
        );
    }

    #[test]
    fn waddles_social_is_registered_as_a_builtin() {
        let registry = builtin_modules();
        assert!(registry.contains_key("waddles-social"));
    }

    #[test]
    fn waddles_social_factory_reports_its_own_identity_before_init() {
        let registry = builtin_modules();
        let factory = registry
            .get("waddles-social")
            .expect("waddles-social registered");
        let info = factory().info();
        assert_eq!(info.name, "waddles-social");
        assert_eq!(info.version, "1.0.0");
        assert!(info.license_feature.is_empty());
    }

    #[test]
    fn waddles_gateway_is_registered_as_a_builtin() {
        let registry = builtin_modules();
        assert!(registry.contains_key("waddles-gateway"));
    }

    #[test]
    fn waddles_gateway_factory_reports_its_own_identity_before_init() {
        let registry = builtin_modules();
        let factory = registry
            .get("waddles-gateway")
            .expect("waddles-gateway registered");
        let info = factory().info();
        assert_eq!(info.name, "waddles-gateway");
        assert_eq!(info.version, "1.0.0");
        assert!(info.license_feature.is_empty());
    }

    #[test]
    fn waddleai_is_registered_as_a_builtin() {
        let registry = builtin_modules();
        assert!(registry.contains_key("waddleai"));
    }

    #[test]
    fn waddleai_factory_reports_its_own_identity_before_init() {
        let registry = builtin_modules();
        let factory = registry.get("waddleai").expect("waddleai registered");
        let info = factory().info();
        assert_eq!(info.name, "waddleai");
        assert_eq!(info.version, "1.0.0");
        assert!(
            info.license_feature.is_empty(),
            "the module itself (shim install/status/telemetry) must load with no license \
             server reachable; the WaddleAI product entitlement is checked server-side when a \
             forwarded hook event is evaluated, not at module load time"
        );
    }
}
