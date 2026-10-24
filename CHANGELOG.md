# TornScope – Changelog

## 3.6 (2026-10-24) – Anti-flicker update
- **Fix:** the overlay no longer jumps back to the top of the list on each 1 s refresh. Cards, War list and feed are only re-drawn when their content really changes, and the panel scroll position is restored when they are.
- **New:** country flags next to flight destinations (targets and War mode).
- **Fix:** version constant and console banner now match the userscript header.

## Ideas queue (next hourly check-ups)
- Sort/filter targets (flying first), compact mode
- Per-card icons on buttons, nicer empty states
- Smarter local history / export (CSV)
- Dashboard (app.tornscope.com is not in this repo): same no-flicker rule for auto-refresh
