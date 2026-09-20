# ADR-004 — Offline: local-first service, no PWA

| Field | Value |
|---|---|
| Status | **Accepted** — 2026-09-20. Sign-off = the operator's merge of the PR that introduces this file. |
| Related | ADR-002 (process model, bind address), ADR-003 (payload) |

---

## Context

- Venues often have no usable Internet. The tool must work at the table.
- ADR-002 runs the whole service on the user's laptop, bound to `127.0.0.1`.
- A PWA's offline capability comes from a service worker. Service workers are exposed only in
  **secure contexts** (W3C Secure Contexts): `https://…`, plus `http://localhost` and
  `http://127.0.0.1`. A tablet reaching the laptop at `http://192.168.x.y:8000` is **not** a
  secure context, so `navigator.serviceWorker` is unavailable there.

## Options

| Option | Offline on the laptop | Offline on a LAN tablet | Cost | Verdict |
|---|:-:|:-:|---|---|
| PWA + service worker | already offline via localhost — no gain | no — not a secure context over plain HTTP | cache invalidation, update bugs, a second copy of every asset | rejected |
| PWA + local TLS | — | yes | installing a local CA on every tablet | rejected |
| Local-first service, no service worker | yes | yes, while the laptop is reachable | the laptop must be at the table | **chosen** |

A service worker would help only the one device that is already offline-capable.

## Decision

### 1. No service worker, no web app manifest.

### 2. Zero third-party origins at runtime

| Rule | Mechanism |
|---|---|
| All JS, CSS, fonts and icons bundled at build | no CDN URLs anywhere in the web source |
| No analytics, telemetry or update checks | none exist in code |
| Enforced by header | FastAPI sets `Content-Security-Policy` with at least `connect-src 'self'; img-src 'self' data: blob:; font-src 'self'`. `script-src` is `NEEDS-VERIFY`: a Next.js App Router static export emits inline scripts, which need hashes or `'unsafe-inline'`. |
| Fonts | system font stack only |

### 3. Eager import

Tiles, thumbnail and `semantic.json` are generated during import, never lazily on first view.
The map list shows a **ready offline** badge only when every artifact exists and its hash
matches the job manifest.

### 4. Updates happen before travel

`docker pull <pinned version>` or `pipx upgrade matsurvey` while online. The software never
checks for updates. Release notes state whether stored maps must be re-imported (`tool_version`
is part of the cache key, ADR-003 §8).

### 5. LAN mode (tablet at the table) — opt-in

| Item | Value |
|---|---|
| How | `matsurvey serve --host 0.0.0.0` or `docker run -p 0.0.0.0:8000:8000 …`, documented next to the exposure warning from ADR-002 §4 |
| Venue Wi-Fi | `ASSUME:` client isolation is common on shared Wi-Fi → recommend the laptop's own hotspot. *If wrong:* harmless; the hotspot works either way. |
| Expectation | works while the laptop is on and reachable; nothing is cached on the tablet |

---

## Consequences

| + | − |
|---|---|
| One source of truth for assets: the local service | phones and tablets have nothing without the laptop |
| No service-worker cache-invalidation bugs | updates need Internet before travel |
| "No third-party requests" is enforced by CSP | strict `script-src` needs build-time hash work |

## Acceptance criteria (verified when the viewer is built)

- [ ] E2E (Playwright): intercept every request; fail if any origin ≠ app origin. Flow: import a synthetic mat → open viewer → measure → export route.
- [ ] Egress test: app and Playwright containers on a Docker network created with `--internal`; the E2E flow passes unchanged.
- [ ] CLI import inside the container with `--network none` succeeds.
- [ ] Responses carry the CSP from §2.
- [ ] The ready-offline badge appears only after all artifacts verify; deleting one tile removes it.
