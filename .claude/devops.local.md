# DevOps Local Override — Per-App Release Branches & Tags (`penguind`)

Overrides the single-release-branch naming in global `devops.md` (`release/v{Major}.{Minor}.X` and `v{Major}.{Minor}.{Patch}`) for this monorepo. Every app/module in `penguind` ships on its own independent release line and tag namespace.

## ⚠️ CRITICAL RULES

- **Release branch naming**: `{app-or-module}/release/v{Major}.{Minor}.X` — use `core` for the base daemon, CLI (`pdcli`), desktop shell, tray, SDK, and shared host crates.
- **Git tag naming**: `{app-or-module}/v{Major}.{Minor}.{Patch}` — use `core` for the base core.
- **Permanent release branches** — never delete `{app-or-module}/release/v*.X` or `main`.
- **No direct merges** — short-lived `feature/`/`fix/`/`chore/`/`hotfix/` branches open PRs targeting the owning app/module's release branch (`{app-or-module}/release/v{Major}.{Minor}.X`).
- **Release → `main` stays user-gated** — explicit human review + approval, never auto-merged.

## App / Module Namespaces

| Scope | Release Branch Pattern | Tag Pattern | Example |
|---|---|---|---|
| **Base (`penguind`, `pdcli`, `desktop`, `penguin-*` core)** | `core/release/v{Major}.{Minor}.X` | `core/v{Major}.{Minor}.{Patch}` | `core/release/v0.1.X`, `core/v0.1.0` |
| **WaddleAI module** | `waddleai/release/v{Major}.{Minor}.X` | `waddleai/v{Major}.{Minor}.{Patch}` | `waddleai/release/v0.1.X`, `waddleai/v0.1.0` |
| **Waddles Social module** | `waddles-social/release/v{Major}.{Minor}.X` | `waddles-social/v{Major}.{Minor}.{Patch}` | `waddles-social/release/v0.1.X`, `waddles-social/v0.1.0` |
| **Waddles Gateway module** | `waddles-gateway/release/v{Major}.{Minor}.X` | `waddles-gateway/v{Major}.{Minor}.{Patch}` | `waddles-gateway/release/v0.1.X`, `waddles-gateway/v0.1.0` |
| **Other modules (e.g., `squawk`, `tobogganing`, `skauswatch`)** | `{module}/release/v{Major}.{Minor}.X` | `{module}/v{Major}.{Minor}.{Patch}` | `squawk/release/v0.1.X`, `squawk/v0.1.0` |

## Cross-Cutting Changes

- Changes touching only one module target `{module}/release/v{Major}.{Minor}.X`.
- Changes touching shared core crates, workspace wiring, or multiple modules target `core/release/v{Major}.{Minor}.X`.
- Legacy `release/v0.1.X` remains until existing open PRs drain; new release lines follow the per-app pattern above.
