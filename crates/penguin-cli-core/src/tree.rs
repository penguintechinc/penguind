//! Builds the full clap [`Command`] tree: the static verbs that always exist
//! (ported from `go-client/cmd/penguin/main.go`), and the per-module subtrees
//! grafted on from the daemon's `ListCommands` response (ported from
//! `go-client/internal/cli/builder.go`'s `BuildRoot`/`buildCommand`).
//!
//! [`build_static_root`] never touches the daemon, so it succeeds even when
//! `penguind` is unreachable — the tree simply has no dynamic parts, and
//! `--help` (or any static verb whose handler prints the friendly
//! daemon-down message itself) still works.

use clap::{Arg, ArgAction, Command};

use crate::flags::build_flag_arg;
use crate::pb;
use crate::socket::DEFAULT_SOCKET_PATH;

/// Arg id for the global `--socket` override.
pub const SOCKET_ARG_ID: &str = "socket";
/// Arg id for the global `--json` output switch.
pub const JSON_ARG_ID: &str = "json";
/// Arg id shared by every static verb's optional/required module-name
/// positional (`load`, `unload`, `status`, `logs`).
pub const MODULE_ARG_ID: &str = "module";
/// Arg id for `logs --follow`.
pub const FOLLOW_ARG_ID: &str = "follow";
/// Arg id for `logs --lines`.
pub const LINES_ARG_ID: &str = "lines";
/// Arg id for `update --yes`.
pub const YES_ARG_ID: &str = "yes";
/// Arg id for a dynamic module command's catch-all positional arguments.
/// Never user-visible under this name — it only appears as a matches lookup
/// key.
pub const ARGS_ID: &str = "args";

/// Builds the root command with every static verb attached, but no dynamic
/// module subtrees — see [`graft_modules`] for adding those once the daemon
/// has answered `ListCommands`.
pub fn build_static_root() -> Command {
    Command::new("pdcli")
        .about("PenguinTech unified endpoint agent")
        .long_about("Manage the penguin daemon and its modules")
        .arg(socket_arg())
        .arg(json_arg())
        .subcommand(Command::new("version").about("Show version information"))
        .subcommand(Command::new("modules").about("List all modules"))
        .subcommand(
            Command::new("load")
                .about("Load a module")
                .arg(module_arg(true)),
        )
        .subcommand(
            Command::new("unload")
                .about("Unload a module")
                .arg(module_arg(true)),
        )
        .subcommand(
            Command::new("status")
                .about("Show status of modules")
                .arg(module_arg(false)),
        )
        .subcommand(
            Command::new("logs")
                .about("Tail daemon or module logs")
                .arg(module_arg(false))
                .arg(
                    Arg::new(FOLLOW_ARG_ID)
                        .long("follow")
                        .help("follow log output")
                        .num_args(0)
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new(LINES_ARG_ID)
                        .long("lines")
                        .help("initial log lines to show")
                        .num_args(1)
                        .default_value("10")
                        .action(ArgAction::Set)
                        .value_parser(clap::value_parser!(i64)),
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Check and apply daemon updates")
                .arg(
                    Arg::new(YES_ARG_ID)
                        .long("yes")
                        .help("apply update without confirmation")
                        .num_args(0)
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(crate::hub::build_hub_command())
}

/// Every name a module cannot use without colliding with a static verb.
/// Go has no equivalent guard — Cobra's `AddCommand` would happily register
/// a second `load` alongside the built-in one, and whichever the internal
/// map iteration order visits last silently wins. Rust's tree is built with
/// chained `Command::subcommand` calls instead, which clap rejects at debug-
/// assertion time for a duplicate name, so a colliding module is skipped
/// here rather than risking that panic. Not required by any test in the M4
/// gate; recorded as a divergence in `docs/PARITY.md`.
const RESERVED_STATIC_VERBS: [&str; 8] = [
    "version", "modules", "load", "unload", "status", "logs", "update", "hub",
];

/// Grafts one top-level [`Command`] per module onto `root`, each carrying
/// that module's own command tree as its subcommands — the
/// `penguin <module> <command>` grammar `BuildRoot`
/// (`go-client/internal/cli/builder.go`) documents. A module that reports no
/// commands at all is skipped, matching Go's `if len(modCmds.Commands) == 0 {
/// continue }`; a module whose name collides with a static verb is also
/// skipped — see [`RESERVED_STATIC_VERBS`].
pub fn graft_modules(mut root: Command, modules: &[pb::ModuleCommands]) -> Command {
    for module in modules {
        if module.commands.is_empty() {
            continue;
        }
        if RESERVED_STATIC_VERBS.contains(&module.module.as_str()) {
            continue;
        }
        let mut module_cmd = Command::new(module.module.clone())
            .about(format!("Commands provided by the {} module", module.module));
        for spec in &module.commands {
            module_cmd = module_cmd.subcommand(build_command_spec(spec));
        }
        root = root.subcommand(module_cmd);
    }
    root
}

/// Recursively builds one module command (and every nested subcommand) from
/// a wire `CommandSpec`, ported from `Builder.buildCommand`
/// (`go-client/internal/cli/builder.go`). `spec.use` (the wire `Use` field)
/// is deliberately not consulted: Go's own builder sets cobra's `Use` from
/// `spec.Name`, never `spec.Use`, so that field is dead data on this path in
/// the frozen reference too — verified against `TestBuilderCommandConstruction`
/// (`go-client/internal/cli/builder_test.go`), which sets `Use: "test
/// [args]"` and then asserts the built command's `Use` equals `"test"` (the
/// name), not the string it set.
pub fn build_command_spec(spec: &pb::CommandSpec) -> Command {
    let mut cmd = Command::new(spec.name.clone());
    if !spec.short.is_empty() {
        cmd = cmd.about(spec.short.clone());
    }
    for flag in &spec.flags {
        cmd = cmd.arg(build_flag_arg(flag));
    }
    if let Some(arg) = args_positional(spec.min_args, spec.max_args) {
        cmd = cmd.arg(arg);
    }
    for sub in &spec.subcommands {
        cmd = cmd.subcommand(build_command_spec(sub));
    }
    cmd
}

/// The catch-all positional argument backing a dynamic command's
/// `min_args`/`max_args` contract, or `None` when `max_args` is `0` — a
/// command that accepts no positional arguments at all gets no positional
/// `Arg` to consume them with, so clap's own "unexpected argument" error
/// enforces that naturally rather than this crate defining a
/// zero-to-zero-width positional (which clap does not treat as meaningful).
///
/// `max_args < 0` means unlimited, matching the wire contract's documented
/// `-1` sentinel; anything else clamps to `[min_args, max_args]` (a
/// `max_args` below `min_args` is nonsensical wire data, so it is raised to
/// `min_args` rather than producing a range clap would reject at build time).
fn args_positional(min_args: i32, max_args: i32) -> Option<Arg> {
    let min = usize::try_from(min_args).unwrap_or(0);
    if max_args == 0 {
        return None;
    }
    let mut arg = Arg::new(ARGS_ID)
        .value_name("ARGS")
        .value_parser(clap::value_parser!(String))
        .allow_hyphen_values(true)
        // Match cobra's `Args` validator (go-client/internal/cli/builder.go),
        // which rejects `len(args) < MinArgs`. clap's `num_args` lower bound
        // only constrains the count when the positional is present — a fully
        // absent positional is not otherwise an error — so a `min_args >= 1`
        // command additionally needs the arg marked required to reject the
        // zero-argument case the way Go does.
        .required(min_args > 0)
        .action(ArgAction::Set);
    // `trailing_var_arg` is only valid on a positional that accepts MULTIPLE
    // values: clap debug-asserts ("must accept multiple values") — and
    // misbehaves in release, where the assert is compiled out — if it is set on
    // a single-value positional. A module command declaring exactly one
    // positional (`min_args >= 1, max_args == 1`, e.g. squawk's `query
    // <domain>`) hits precisely that case, so gate the flag on the arg actually
    // being multi-valued: `max_args` outside `0..=1` — i.e. unbounded (`-1`) or
    // an explicit upper bound above 1.
    if !(0..=1).contains(&max_args) {
        arg = arg.trailing_var_arg(true);
    }
    let arg = if max_args < 0 {
        arg.num_args(min..)
    } else {
        let max = usize::try_from(max_args).unwrap_or(min).max(min);
        arg.num_args(min..=max)
    };
    Some(arg)
}

/// The `--socket` global flag: available at every level of the tree, since
/// Rust accepts it in more positions than Go does (see `docs/PARITY.md`).
/// Its parsed value here is for `--help` display only — the value actually
/// used to dial the daemon comes from
/// [`crate::socket::extract_socket_override`], resolved before this tree can
/// even be built.
fn socket_arg() -> Arg {
    Arg::new(SOCKET_ARG_ID)
        .long("socket")
        .help("daemon socket path")
        .global(true)
        .num_args(1)
        .default_value(DEFAULT_SOCKET_PATH)
        .action(ArgAction::Set)
        .value_parser(clap::value_parser!(String))
}

/// The `--json` global flag, read by `modules` and `status` to switch their
/// output format.
fn json_arg() -> Arg {
    Arg::new(JSON_ARG_ID)
        .long("json")
        .help("output JSON")
        .global(true)
        .num_args(0)
        .action(ArgAction::SetTrue)
}

/// The `module` positional shared by `load`/`unload` (required) and
/// `status`/`logs` (optional).
fn module_arg(required: bool) -> Arg {
    Arg::new(MODULE_ARG_ID)
        .required(required)
        .action(ArgAction::Set)
        .value_parser(clap::value_parser!(String))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_modules() -> Vec<pb::ModuleCommands> {
        vec![pb::ModuleCommands {
            module: "test-module".to_string(),
            commands: vec![pb::CommandSpec {
                name: "test-cmd".to_string(),
                short: "Test command".to_string(),
                flags: vec![pb::FlagSpec {
                    name: "verbose".to_string(),
                    r#type: "bool".to_string(),
                    ..Default::default()
                }],
                min_args: 0,
                max_args: -1,
                ..Default::default()
            }],
        }]
    }

    #[test]
    fn static_root_has_every_verb() {
        let root = build_static_root();
        let names: Vec<&str> = root.get_subcommands().map(Command::get_name).collect();
        for verb in [
            "version", "modules", "load", "unload", "status", "logs", "update",
        ] {
            assert!(names.contains(&verb), "missing static verb {verb}");
        }
    }

    #[test]
    fn empty_module_list_still_yields_a_working_static_tree() {
        let root = graft_modules(build_static_root(), &[]);
        let matches = root
            .try_get_matches_from(["pdcli", "version"])
            .expect("static verb still parses with no modules loaded");
        assert_eq!(matches.subcommand_name(), Some("version"));
    }

    #[test]
    fn module_colliding_with_a_static_verb_name_is_skipped() {
        let modules = vec![pb::ModuleCommands {
            module: "load".to_string(),
            commands: vec![pb::CommandSpec {
                name: "anything".to_string(),
                ..Default::default()
            }],
        }];
        // Must not panic building the tree, and the static `load` verb must
        // still be the one that wins.
        let root = graft_modules(build_static_root(), &modules);
        let load_cmd = root.find_subcommand("load").expect("static load survives");
        assert_eq!(
            load_cmd.get_about().map(|s| s.to_string()),
            Some("Load a module".to_string())
        );
    }

    #[test]
    fn a_module_is_grafted_as_a_top_level_command() {
        let root = graft_modules(build_static_root(), &sample_modules());
        let names: Vec<&str> = root.get_subcommands().map(Command::get_name).collect();
        assert!(names.contains(&"test-module"));
    }

    #[test]
    fn nested_subcommand_is_reachable_under_its_module() {
        let root = graft_modules(build_static_root(), &sample_modules());
        let module_cmd = root.find_subcommand("test-module").expect("module grafted");
        let names: Vec<&str> = module_cmd
            .get_subcommands()
            .map(Command::get_name)
            .collect();
        assert!(names.contains(&"test-cmd"));
    }

    #[test]
    fn module_with_no_commands_is_skipped() {
        let modules = vec![pb::ModuleCommands {
            module: "empty-module".to_string(),
            commands: vec![],
        }];
        let root = graft_modules(build_static_root(), &modules);
        assert!(root.find_subcommand("empty-module").is_none());
    }

    #[test]
    fn recursive_nesting_builds_the_full_chain() {
        let spec = pb::CommandSpec {
            name: "parent".to_string(),
            subcommands: vec![pb::CommandSpec {
                name: "child".to_string(),
                subcommands: vec![pb::CommandSpec {
                    name: "grandchild".to_string(),
                    max_args: -1,
                    ..Default::default()
                }],
                max_args: 0,
                ..Default::default()
            }],
            max_args: 0,
            ..Default::default()
        };
        let cmd = build_command_spec(&spec);
        let matches = Command::new("root")
            .subcommand(cmd)
            .try_get_matches_from(["root", "parent", "child", "grandchild", "extra"])
            .expect("nested parse");

        let (name, sub) = matches.subcommand().expect("parent matched");
        assert_eq!(name, "parent");
        let (name, sub) = sub.subcommand().expect("child matched");
        assert_eq!(name, "child");
        let (name, sub) = sub.subcommand().expect("grandchild matched");
        assert_eq!(name, "grandchild");
        let args: Vec<&String> = sub.get_many::<String>(ARGS_ID).unwrap().collect();
        assert_eq!(args, vec!["extra"]);
    }

    #[test]
    fn min_args_violation_is_rejected() {
        let spec = pb::CommandSpec {
            name: "needs-two".to_string(),
            min_args: 2,
            max_args: -1,
            ..Default::default()
        };
        let cmd = Command::new("root").subcommand(build_command_spec(&spec));
        assert!(
            cmd.clone()
                .try_get_matches_from(["root", "needs-two", "a"])
                .is_err()
        );
        assert!(
            cmd.try_get_matches_from(["root", "needs-two", "a", "b"])
                .is_ok()
        );
    }

    #[test]
    fn max_args_violation_is_rejected() {
        let spec = pb::CommandSpec {
            name: "at-most-two".to_string(),
            min_args: 0,
            max_args: 2,
            ..Default::default()
        };
        let cmd = Command::new("root").subcommand(build_command_spec(&spec));
        assert!(
            cmd.clone()
                .try_get_matches_from(["root", "at-most-two", "a", "b"])
                .is_ok()
        );
        assert!(
            cmd.try_get_matches_from(["root", "at-most-two", "a", "b", "c"])
                .is_err()
        );
    }

    #[test]
    fn exactly_one_required_positional_builds_without_panicking() {
        // Regression: `args_positional` unconditionally set `trailing_var_arg`,
        // which clap forbids on a single-value positional — so any module
        // command with `min_args: 1, max_args: 1` (e.g. squawk `query
        // <domain>`) panicked clap's debug assertion while the tree was built,
        // making `penguin squawk query ...` (and its `--help`) unusable. The
        // parity harness's cli-tree gate caught this; this pins it at the unit
        // level. Building and parsing must succeed, and the `1..=1` bound must
        // still be enforced.
        let spec = pb::CommandSpec {
            name: "one-arg".to_string(),
            min_args: 1,
            max_args: 1,
            ..Default::default()
        };
        let cmd = Command::new("root").subcommand(build_command_spec(&spec));
        // `--help` forces clap to `_build_self` the subcommand (the path that
        // panicked before the fix); it must yield a clean help error, never a
        // panic.
        let help = cmd
            .clone()
            .try_get_matches_from(["root", "one-arg", "--help"]);
        assert!(
            help.is_err(),
            "--help should short-circuit into a help error"
        );
        assert!(
            cmd.clone()
                .try_get_matches_from(["root", "one-arg"])
                .is_err(),
            "zero args must be rejected (min_args = 1)"
        );
        assert!(
            cmd.clone()
                .try_get_matches_from(["root", "one-arg", "example.com"])
                .is_ok(),
            "exactly one arg must be accepted"
        );
        assert!(
            cmd.try_get_matches_from(["root", "one-arg", "a", "b"])
                .is_err(),
            "two args must be rejected (max_args = 1)"
        );
    }

    #[test]
    fn negative_max_args_means_unlimited() {
        let spec = pb::CommandSpec {
            name: "unlimited".to_string(),
            min_args: 0,
            max_args: -1,
            ..Default::default()
        };
        let cmd = Command::new("root").subcommand(build_command_spec(&spec));
        let many: Vec<String> = (0..50).map(|n| n.to_string()).collect();
        let mut argv = vec!["root".to_string(), "unlimited".to_string()];
        argv.extend(many);
        assert!(cmd.try_get_matches_from(argv).is_ok());
    }

    #[test]
    fn default_zero_min_and_max_args_allows_no_positional_args() {
        let spec = pb::CommandSpec {
            name: "no-args".to_string(),
            ..Default::default()
        };
        let cmd = Command::new("root").subcommand(build_command_spec(&spec));
        assert!(
            cmd.clone()
                .try_get_matches_from(["root", "no-args"])
                .is_ok()
        );
        assert!(cmd.try_get_matches_from(["root", "no-args", "x"]).is_err());
    }
}
