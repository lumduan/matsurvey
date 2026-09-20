# ADR-003 — Browser payload: tile pyramid + semantic layer

| Field | Value |
|---|---|
| Status | **Accepted** — 2026-09-20. Sign-off = the operator's merge of the PR that introduces this file. |
| Related | ADR-002 (memory budget, headers), ADR-004 (offline) |

All numeric examples use a **2000 × 1000 mm** example mat. Real sizes come from the user's
profile (ADR-001 §3, C6).

---

## Context

- A full frame at 8 px/mm of the example mat is 128,000,000 px → 512,000,000 B of decoded RGBA
  in the browser. Tiles are required because of **decode memory**, not bandwidth.
- The raw vector dump of a detailed real mat reaches the order of 10² MB (measured locally). It
  must never reach a browser.
- Snapping must be as exact as the vector artwork, so it cannot depend on raster resolution.

## Decision

### 1. Coordinates: 1 map unit = 1 mm

- `lng = x_mm`, `lat = y_mm`, mat frame with origin bottom-left and +Y up.
- `MEASURED(Leaflet v1.9.4, src/geo/crs/CRS.Simple.js)`: `transformation: toTransformation(1, 0, -1, 0)`
  and `scale(zoom) = 2^zoom` ⇒ pixel y = −lat · 2^z, so **+lat renders upward** and
  **px/mm = 2^z** (z = 3 ↔ 8 px/mm).
- Stock `CRS.Simple` places a mat at lat ∈ [0, H] at negative pixel y → negative tile rows. Use a
  custom CRS: `CRS.Simple` with `transformation(1, 0, -1, H)`. Leaflet applies
  `y' = scale · (c·y + d)`, so pixel y = 2^z · (H − y): the top edge is pixel row 0 and every tile
  index is ≥ 0. H comes from the map's profile at runtime.
- Pin Leaflet **1.9.x**. Its `main` branch is a restructured 2.0 line and is not tracked.
- `NEEDS-VERIFY(empirical)`: the synthetic fiducial (asymmetric) must appear in the expected
  screen position at z = −4 … 5 in Chromium, WebKit and Firefox.

### 2. Payload inventory

| Artifact | Format | Size | Loaded |
|---|---|---|---|
| Tile pyramid | WebP, 256 × 256 | `NEEDS-MEASURE` | on demand |
| `semantic.json` | JSON, gzip on the wire | `ASSUME: < 1 MB` — *if wrong:* first paint slows; fix by per-layer lazy loading | once per map |
| Thumbnail | WebP at 0.25 px/mm | small | map list |
| `field_spec.json` | JSON | — | export only; never loaded by the viewer |
| Raw vector dump | — | order of 10² MB | **never served** |

### 3. Pyramid

`tiles(z) = ceil(W·2^z / 256) · ceil(H·2^z / 256)` for z from 3 down to the first level with a
single tile. Example mat:

| z | px/mm | frame (px) | tiles |
|--:|--:|--:|--:|
| 3 | 8 | 16,000 × 8,000 | 2,016 |
| 2 | 4 | 8,000 × 4,000 | 512 |
| 1 | 2 | 4,000 × 2,000 | 128 |
| 0 | 1 | 2,000 × 1,000 | 32 |
| −1 | 0.5 | 1,000 × 500 | 8 |
| −2 | 0.25 | 500 × 250 | 2 |
| −3 | 0.125 | 250 × 125 | 1 |
| | | **total** | **2,699** |

`maxNativeZoom = 3`; `maxZoom = 5` (overzoom for precise clicking — accuracy comes from snapping,
§7, not from pixels).

### 4. No separate overview image

The pyramid's z = 1 level is already 2 px/mm; a separate overview at that scale would duplicate
it. Only the 0.25 px/mm thumbnail exists outside the pyramid.

### 5. Tile generation: per-tile render from a MuPDF DisplayList

Build `page.get_displaylist()` once; render each tile with `dl.get_pixmap(matrix=M, clip=tile_rect)`.
Memory per tile ≈ 256² × 4 B; no full frame is ever materialised; no external tiler dependency.

`MEASURED` (PyMuPDF 1.28.0 / MuPDF 1.29.0; synthetic large-format page; 2 px/mm RGB; stitched
256-px tiles compared with the same crop of one full-frame render):

| Content | tiles differing | max \|Δ\| (0–255) |
|---|--:|--:|
| flat CMYK fills | 0 | 0 |
| flat fill under ExtGState `ca 0.5` | 0 | 0 |
| small Bézier dots at fractional positions | 8 | 1 |
| axial shading (`sh`) inside a clip | 14 | 4 |
| wide diagonal stroke | 30 | 14 |

⇒ **A tiled render is not byte-identical to a crop of a full render**: curve flattening, shading
subdivision and stroke rasterisation depend on the clip. Therefore:

- tiles are **display-only** (colour layer L2) and never an input to segmentation, palette or
  sensor modelling;
- the analysis render is a separately specified artifact (future ADR);
- tile determinism is defined per tile (same clip → same bytes) and tested run-to-run.

Rejected: an external tiler (e.g. `pyvips dzsave`) fed from a full frame — the frame must first
exist as one 384–512 MB pixmap (example mat), and it adds a native dependency to the image.

### 6. Tiles are display colour only

Tile colours are profile-less sRGB approximations. The area inspector shows the source colour
from `semantic.json`, never a value sampled from a tile. WebP lossy vs lossless: `NEEDS-MEASURE`
on the synthetic corpus before freezing.

### 7. `semantic.json` and snapping

| Field | Content |
|---|---|
| `regions[]` | `region_id`, polygon (mm, 3 decimals), `area_id` if labelled locally, `border_policy`, source colour + colour space, display hex |
| `lines[]` | centreline polyline, width, edge colours on both sides |
| `snap[]` | vertices, edges (nearest point on segment), centroids, line centrelines |
| `meta` | `source_sha256`, `tool_version`, `platform`, frame, profile reference |

The client builds an R-tree (`rbush`) over snap targets. Snap precision = vector precision
(1 µm), independent of zoom. If a real mat exceeds the size budget, the fix is transport (gzip)
or lazy per-layer loading — **never** polygon simplification, which would change geometry.

### 8. HTTP caching

`/v1/maps/{sha}/{tool_version}/{platform}/tiles/{z}/{x}/{y}.webp` with
`Cache-Control: public, max-age=31536000, immutable`. Without `tool_version` and `platform` in
the path, a tool upgrade would serve stale cached tiles under an unchanged URL.

---

## Consequences

| + | − |
|---|---|
| Browser memory bounded by visible tiles | thousands of tile files per map on disk |
| No full-frame buffer anywhere in the tile path | tile seams can differ from a full render by up to 14/255 on diagonal strokes (display only) |
| Snapping exact and zoom-independent | `semantic.json` size is an assumption until measured |
| mm are native map units — no scale factor in app code | the custom CRS must be tested per browser engine |

## Acceptance criteria (verified when the viewer is built)

- [ ] Fiducial test passes at z = −4 … 5 in Chromium, WebKit, Firefox.
- [ ] Tile bytes per zoom level and total, generation time and peak RSS reported for the synthetic corpus.
- [ ] Two tile runs byte-identical per tile.
- [ ] `semantic.json` size reported; CI budget assertion on synthetic mats.
