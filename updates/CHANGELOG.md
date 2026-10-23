# TornScope – Changelog

Newest first. Each hourly check-up adds one small, tested step.

## v3.6 – 2026-10-23
### Fixed
- **Scroll jump on refresh**: the target list, War list, War feed and Premium note were rebuilt
  every second, which sent the panel back to the top while scrolling. They now skip identical
  markup and restore the panel's scroll position after each refresh.
- Version constant (`VERSION`) and console log now match the `@version` header (were stuck on 3.4).

## v3.5 and earlier
See git history (War mode, Premium server tracking, sync, alarms).
