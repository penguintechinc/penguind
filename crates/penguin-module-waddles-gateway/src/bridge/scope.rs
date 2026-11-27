//! The bridge's permission model: a small, fixed set of hub-relayed
//! [`Operation`]s, each requiring exactly one [`Scope`] — the unit a
//! per-script [`crate::bridge::token::ScriptIdentity`] is granted or denied.
//!
//! Deliberately coarse (one scope per operation, six operations total) —
//! see `bridge`'s module doc for why this track keeps the relayed surface
//! small rather than mirroring every `waddles-client` method.

use std::collections::HashSet;

/// One permission a script identity can hold. An OBS overlay script that
/// only ever needs [`Scope::BrowserSourceRead`] has no way to also reach
/// [`Scope::MusicWrite`] — the scenario this whole model exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `status` — a cheap hub connectivity/community probe.
    Status,
    /// `music.get` — read the community's music settings.
    MusicRead,
    /// `music.update` — write the community's music settings.
    MusicWrite,
    /// `announcements.list` — read announcements.
    AnnouncementRead,
    /// `announcements.create` — create an announcement.
    AnnouncementWrite,
    /// `browser_sources.list` — read OBS browser-source overlay URLs.
    BrowserSourceRead,
}

impl Scope {
    /// Every scope this bridge knows about — the grant a name in
    /// `bridge.allowed_integrations` receives today, since
    /// [`crate::config::BridgeSection`] has no per-integration scope field
    /// yet (a natural follow-up once an operator-facing way to narrow a
    /// script's grant is added). [`crate::bridge::token::TokenRegistry::register`]
    /// also accepts a narrower, hand-picked set directly — what every
    /// scope-enforcement test in this crate exercises.
    pub fn all() -> HashSet<Scope> {
        HashSet::from([
            Scope::Status,
            Scope::MusicRead,
            Scope::MusicWrite,
            Scope::AnnouncementRead,
            Scope::AnnouncementWrite,
            Scope::BrowserSourceRead,
        ])
    }
}

/// One hub call the bridge is willing to relay on a script's behalf. Each
/// variant is a thin, typed stand-in for one `op` string in a
/// [`crate::bridge::http::RpcRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    GetStatus,
    GetMusicSettings,
    UpdateMusicSettings,
    ListAnnouncements,
    CreateAnnouncement,
    ListBrowserSources,
}

impl Operation {
    /// Parses the wire `op` string a request names. Unrecognized input
    /// returns `None` — callers must treat that as fail-closed (no scope
    /// can authorize an operation nothing here recognizes), never as
    /// "no scope required".
    pub fn parse(name: &str) -> Option<Operation> {
        match name {
            "status" => Some(Operation::GetStatus),
            "music.get" => Some(Operation::GetMusicSettings),
            "music.update" => Some(Operation::UpdateMusicSettings),
            "announcements.list" => Some(Operation::ListAnnouncements),
            "announcements.create" => Some(Operation::CreateAnnouncement),
            "browser_sources.list" => Some(Operation::ListBrowserSources),
            _other => None,
        }
    }

    /// The one scope a script identity must hold to invoke this operation.
    pub fn required_scope(self) -> Scope {
        match self {
            Operation::GetStatus => Scope::Status,
            Operation::GetMusicSettings => Scope::MusicRead,
            Operation::UpdateMusicSettings => Scope::MusicWrite,
            Operation::ListAnnouncements => Scope::AnnouncementRead,
            Operation::CreateAnnouncement => Scope::AnnouncementWrite,
            Operation::ListBrowserSources => Scope::BrowserSourceRead,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_op_string_round_trips_to_a_scope() {
        let cases = [
            ("status", Scope::Status),
            ("music.get", Scope::MusicRead),
            ("music.update", Scope::MusicWrite),
            ("announcements.list", Scope::AnnouncementRead),
            ("announcements.create", Scope::AnnouncementWrite),
            ("browser_sources.list", Scope::BrowserSourceRead),
        ];
        for (raw, want_scope) in cases {
            let op = Operation::parse(raw).unwrap_or_else(|| panic!("{raw} must parse"));
            assert_eq!(op.required_scope(), want_scope);
        }
    }

    #[test]
    fn unknown_op_string_fails_to_parse() {
        assert!(Operation::parse("bogus.operation").is_none());
        assert!(Operation::parse("").is_none());
    }

    #[test]
    fn scope_all_contains_every_variant_exactly_once() {
        let all = Scope::all();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&Scope::Status));
        assert!(all.contains(&Scope::MusicRead));
        assert!(all.contains(&Scope::MusicWrite));
        assert!(all.contains(&Scope::AnnouncementRead));
        assert!(all.contains(&Scope::AnnouncementWrite));
        assert!(all.contains(&Scope::BrowserSourceRead));
    }
}
