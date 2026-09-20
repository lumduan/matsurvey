# ADR-002 — Packaging: one container, one port, plus a pip route

| Field | Value |
|---|---|
| Status | **Accepted** — 2026-09-20. Sign-off = the operator's merge of the PR that introduces this file. |
| Related | ADR-001 (`.dockerignore`), ADR-003 (tiles, memory), ADR-004 (offline, LAN) |

---

## Context

- Target users run the tool on personal laptops, including Apple Silicon. Many do not use Docker.
- The pipeline is memory-bound before it is CPU-bound. A full frame at `p` px/mm for a
  W × H mm mat holds `W·p · H·p` pixels. Example, 2000 × 1000 mm at 8 px/mm:
  16,000 × 8,000 = 128,000,000 px → 512,000,000 B at 4 channels, 384,000,000 B at 3.
- Earlier timings from the predecessor toolchain were taken on a large workstation and are not
  a sizing basis for an 8 GB laptop.
- `MEASURED(PyPI, 2026-09-19)` — `pymupdf==1.28.0` wheels:

  | Platform tag | Present |
  |---|:-:|
  | `manylinux_2_28_x86_64`, `manylinux_2_28_aarch64` | ✓ |
  | `musllinux_1_2_x86_64` | ✓ |
  | `musllinux_1_2_aarch64` | **✗** — Alpine on arm64 would build MuPDF from source |
  | `macosx_11_0_arm64`, `macosx_10_15_x86_64`, `win32`, `win_amd64` | ✓ |
  | `cp313-abi3-pyemscripten_2025_0_wasm32` | ✓ (option D) |

  CPython wheels are `cp310-abi3` → Python ≥ 3.10 for any pip route.
- `MEASURED(nextjs.org/docs/app/guides/static-exports)`: with `output: 'export'`, dynamic routes
  without `generateStaticParams()` are unsupported; features needing a Node server (image
  optimisation, rewrites/redirects/headers, middleware) are unavailable.

## Options

| | Option | For | Against | Verdict |
|---|---|---|---|---|
| A | One image: FastAPI serves the static web export + a job runner | one command, one port, no Node at runtime | image carries the whole pipeline | **chosen** |
| B | Compose: web + api + worker + queue | textbook separation | multi-container setup for end users; nothing gained at one user per host | rejected |
| C | Python wheel with the web export bundled: `pipx install matsurvey && matsurvey serve` | no Docker; the same bytes the image contains | needs Python ≥ 3.10 on the host | **chosen as complement** |
| D | Browser-only: Pyodide + the PyMuPDF wasm wheel as a static site | zero install; the PDF never leaves the browser | wasm32 has a 4 GiB address space; single-thread speed unknown; Pyodide ABI must match | **deferred** — revisit with measurements at the MVP-0 gate |

## Decision

### 1. Artifacts

| Artifact | Decision |
|---|---|
| Wheel | contains the Python package **and** the built web export; entry point `matsurvey serve` |
| Image | `ghcr.io/lumduan/matsurvey:<semver>`; `linux/amd64` + `linux/arm64`; glibc base (Debian slim), not Alpine; multi-stage (Node builds the web export, the runtime stage installs the wheel); no Node in the final image; non-root; volume `/data`; `HEALTHCHECK` on `/v1/health`; OCI labels with source, revision, licenses and the neutral description |
| Build context | `.dockerignore` allowlist (ADR-001 §5) |

The image is the wheel plus a runtime: one artifact, two ways to run it.

### 2. Process model

```
uvicorn (one process)
 ├─ /v1/*   FastAPI routers
 ├─ /       StaticFiles(web export, html=True)   ← mounted last
 └─ job queue (FIFO, concurrency 1)
      └─ asyncio.create_subprocess_exec("python", "-m", "matsurvey.worker", job_dir)
           one child per job; parses the untrusted PDF; writes outputs; exits
```

| Rule | Mechanism |
|---|---|
| One child process per job, not `ProcessPoolExecutor` | if the kernel OOM-kills a pool worker, CPython marks the whole pool broken (`BrokenProcessPool`) and every pending future fails; a per-job child confines the failure to one job |
| The untrusted PDF is parsed only in the child | a crash or hang on a hostile file cannot take the API down |
| Concurrency 1 by default | memory-bound; two concurrent high-resolution jobs double peak RSS |
| Job state is a file | `/data/jobs/<id>/state.json`, written temp + `rename`; on startup `running` → `failed: interrupted` |
| Content addressing | `/data/maps/<source_sha256>/<tool_version>/<platform>/…` |
| Peak memory is measured | the parent records `resource.getrusage(RUSAGE_CHILDREN).ru_maxrss` per stage into the job manifest |

### 3. Static web under `output: 'export'`

| Constraint | Consequence | Response |
|---|---|---|
| Dynamic routes need `generateStaticParams`; unknown params 404 | `/maps/[sha]` is impossible — the sha is unknown at build time | `/map/?sha=<sha256>` |
| No server image optimisation | default `next/image` loader fails | `images: { unoptimized: true }` or plain `<img>` |
| Prerender runs at build with no `window` | Leaflet touches `window` on import | client component + dynamic import with `ssr: false` |
| No rewrites / redirects / headers / middleware | cache and CSP headers cannot come from Next.js | FastAPI sets them |

`trailingSlash: true` emits `map/index.html`, which Starlette `StaticFiles(..., html=True)` serves
for `/map/`. The static mount at `/` is registered after the `/v1` routers; a root mount
registered first would shadow them. `NEEDS-VERIFY`: both behaviours on the pinned versions.

### 4. Network exposure

| Item | Decision |
|---|---|
| Default bind | **`127.0.0.1`** — `matsurvey serve` binds loopback; docs use `docker run -p 127.0.0.1:8000:8000 …` |
| Why | publishing on all interfaces exposes the import API and every stored map to whoever shares the network |
| LAN access | opt-in (ADR-004 §5) |
| Upload guard | `%PDF-` within the first 1024 bytes; size cap 100 MB; rejected before any parse |

### 5. Memory budget

| Item | Decision |
|---|---|
| Reference host | `ASSUME:` 8 GB laptop running Docker Desktop; its VM memory default is `NEEDS-VERIFY` per OS and version. *If wrong:* jobs OOM on the machines users actually own. |
| Rule | no stage holds more than one full high-resolution frame at a time |
| Tiles | rendered per tile, never cut from a full frame (ADR-003 §5) |
| Evidence | per-stage peak RSS is part of every job manifest and every release note |

### 6. Reproducibility across architectures

| Item | Value |
|---|---|
| Established | byte-identical outputs across repeated runs **on one host** (predecessor toolchain) |
| Unverified | amd64 ↔ arm64 |
| Mechanism for divergence | GCC defaults to `-ffp-contract=fast` in GNU C modes. On aarch64, FMA is baseline, so `a*b+c` may fuse into one rounding; x86-64 baseline builds round twice. Rasteriser coverage and rounded coordinates can then differ. NumPy's per-arch SIMD dispatch can change reduction order the same way. |
| Decision | `platform` is part of the cache key and of local golden manifests until a cross-arch run over the synthetic corpus shows identity; dropping it needs a new ADR |

---

## Consequences

| + | − |
|---|---|
| One command, one port, no Node at runtime | image size `NEEDS-MEASURE` |
| Users without Docker can still run it (wheel) | a Python ≥ 3.10 support matrix to test |
| OOM or a hostile PDF kills one job, not the service | per-job process start cost |
| Loopback default closes network exposure | tablet use needs one documented flag |
| Arch divergence is surfaced, not hidden | golden manifests double until identity is proven |

## Acceptance criteria (verified when the service is built)

- [ ] `matsurvey serve` and `docker run --rm -p 127.0.0.1:8000:8000 -v "$PWD/data:/data" <image>` both serve the UI at `/` and `200` on `/v1/health`, on amd64 and on real Apple Silicon.
- [ ] Final image contains no `node` binary; compressed size reported per arch.
- [ ] `kill -9` of a job child → that job `failed`, API healthy, next job completes.
- [ ] Per-stage peak RSS of the full synthetic pipeline at 8 px/mm reported.
- [ ] Cross-arch manifest diff over the synthetic corpus reported.
