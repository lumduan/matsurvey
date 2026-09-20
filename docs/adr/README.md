# Architecture decision records

Format: context → options → decision → consequences. An ADR is **Accepted** when the operator
merges the PR that introduces it. Changing an accepted decision needs a new ADR that supersedes it.

| ADR | Title | Status |
|---|---|---|
| [ADR-001](0001-license-content-policy-change-control.md) | License, content policy and change control | Accepted |
| [ADR-002](0002-packaging.md) | Packaging: one container, one port, plus a pip route | Accepted |
| [ADR-003](0003-browser-payload.md) | Browser payload: tile pyramid + semantic layer | Accepted |
| [ADR-004](0004-offline-no-pwa.md) | Offline: local-first service, no PWA | Accepted |

Spec: [synthetic mat generator](../specs/synthetic-mat-generator.md) — Accepted.

## Decision log

| Decision | Recorded in |
|---|---|
| License AGPL-3.0-or-later | ADR-001 §1 |
| No third-party references anywhere in the repository; open-source software names allowed | ADR-001 §2 |
| Output fingerprints of real sources stay local | ADR-001 §3 (C4) |
| Area labels are user-local, shared as files outside the repository | ADR-001 §3–4 (C5) |
| Nominal mat size is a user-supplied profile; the code has no default mat size | ADR-001 §3 (C6) · spec G9 |
| Contributor terms: DCO | ADR-001 §7 |
| Two-person rule via a separate agent account + 1 required approval, before porting code | ADR-001 §7 |
| Wheel with bundled web export as a second distribution route | ADR-002 §1 |
| Default bind address `127.0.0.1` | ADR-002 §4 |
| No separate overview image; thumbnail only | ADR-003 §4 |
| Tiles rendered per tile from a MuPDF DisplayList | ADR-003 §5 |
| Mat-size tolerance ±0.5 mm (profile default) | spec §4 (S05), §8 |
| Synthetic PDFs generated at test time, never committed | spec §1 |
