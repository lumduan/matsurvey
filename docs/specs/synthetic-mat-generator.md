# Spec — synthetic mat generator (`scripts/gen_synthetic_mat.py`)

| Field | Value |
|---|---|
| Status | **Accepted** — 2026-09-20. Sign-off = the operator's merge of the PR that introduces this file. |
| Consumers | probe, render, segment, snap and palette tests; public CI; the ADR-003 fiducial test |

---

## 1. Purpose

Public CI cannot touch real mats (ADR-001). Every behaviour the pipeline promises must be
provable on PDFs whose ground truth is known **exactly**, generated from code. The generator is
the only source of test PDFs, and PDFs are never committed: they are generated at test time.

## 2. Design decisions

| # | Decision | Reason |
|---|---|---|
| G1 | **Hand-rolled PDF writer, standard library only** (objects, content streams, xref computed by the writer) | tests need operator-level control: `m l l l h` vs `re`, literal strings containing operator-like bytes, `<<` inside marked content, exact clip nesting. High-level writers normalise these away. |
| G2 | **Never generate with MuPDF / PyMuPDF** | MuPDF is the system under test; writing its inputs with its own writer makes a shared misreading pass on both sides |
| G3 | Independent validation | every generated file passes `qpdf --check` in CI (except S31, malformed by design) and is re-read by `pdfminer.six` for page boxes and object counts |
| G4 | **Byte-deterministic output** | no `/Info` dates; `/ID` = two copies of the first 16 bytes of sha256 over the body; fixed object order; fixed float formatting; `random.Random(seed)` only |
| G5 | **No zlib** | Python's `zlib` links whatever the system provides, and zlib-ng-based builds emit different deflate bytes for the same input. Content streams stay uncompressed; images use `RunLengthDecode`, implemented in the generator. |
| G6 | **Truth is computed from emitted bytes** | coordinates are formatted to pt first; truth in mm is computed from the formatted pt values, never from the intended mm |
| G7 | Exact areas for curved outlines | Bézier-bounded areas in closed form (Green's theorem on cubic segments), so tests measure the pipeline's flattening error instead of comparing one flattening with another |
| G8 | Every mat carries an **asymmetric fiducial** | an L-shape plus an offset dot at a fixed position: mirroring and rotation become testable |
| G9 | **Sizes come from a profile** | the generator takes a mat profile (nominal W × H mm, placement); the repo ships only synthetic example profiles. Default example: 2000 × 1000 mm. |

## 3. Primitives (mat frame, mm)

| Primitive | Parameters | Emits |
|---|---|---|
| `Area` | outline (polygon · rect · rounded rect · ellipse via 4 cubics), fill colour + colour space | fill operator + path + `f` |
| `BorderedArea` | inner `Area`, ring width, ring colour | two fills; truth carries inner, ring and union polygons |
| `Line` | polyline, width, cap, join, colour | stroke only; truth = centreline + buffered polygon |
| `Speckle` | base `Area`, dot colour, dot radius range, `outlier_fraction` (default 0.15) | base fill + seeded dots |
| `Foliage` | bbox, count, size range | many tiny closed paths |
| `Raster` | generated pixel grid, colour space, placement matrix | image XObject + `cm` + `Do` |
| `Group` | children + clip, ExtGState, optional-content group or Form XObject | `q … Q`, `W n`, `gs`, `BDC … EMC`, `Do` |
| `DecoyText` | literal and hex strings | `BT … Tj … ET` with a standard Type1 font (no embedding) |

## 4. Case matrix

Priority **A** = needed for MVP-0 · **B** = later.

| ID | Pri | Case | Construction | Expected | Covers |
|---|:-:|---|---|---|---|
| S01 | A | vector baseline | TrimBox = MediaBox = profile size; rects, rounded rect, ellipse, bordered area, fiducial | `VECTOR`; polygons within 1e-3 mm; areas vs closed form | baseline, G7, G8 |
| S02 | A | bleed + crop marks | MediaBox = Trim + 9 pt per side; artwork into bleed; crop marks outside trim | frame from TrimBox; offset recorded; marks excluded | bleed |
| S03 | A | bleed, no TrimBox/CropBox | as S02 without Trim/Crop | MediaBox ≠ profile size → **hard fail**, message suggests bleed | size check |
| S04 | A | wrong size | page 10 % larger than the profile on both axes | **hard fail** | size check |
| S05 | A | size tolerance | Trim = profile size exactly; profile size rounded to 2 decimals in pt; profile size + 1.5 mm | pass · pass · fail (tolerance ±0.5 mm) | size check |
| S06 | B | non-zero origin | MediaBox with negative origin; TrimBox offset | frame translated (fiducial) | box precedence |
| S07 | B | `/Rotate 90` | portrait boxes + rotate | rotation reported; frame correct (fiducial) | orientation |
| S08 | B | `/UserUnit 2.0` | half-size boxes | `/UserUnit ≠ 1` detected → hard fail until supported. `NEEDS-VERIFY`: whether MuPDF applies UserUnit | physical size |
| S09 | A | raster-only | full-mat image at 1 px/mm, no vector painting ops | `RASTER`; **no division by zero** when painting ops = 0; contour error ≤ ½ native px | raster |
| S10 | A | raster + vector marks | S09 + vector crop/registration marks | still `RASTER` although paths-per-painting-op = 1.0 (§6) | classifier |
| S11 | B | hybrid | raster background + vector areas | `HYBRID`; vector areas snapped, raster regions contoured | classifier |
| S12 | A | spot colour | area in `Separation(All, DeviceCMYK)`; image in the same space | spot flagged; image encodes via the fallback chain; CMYK-vs-RGB render diff localises it | spot colour |
| S13 | B | DeviceN | 2-colorant fill | flagged like S12 | spot colour |
| S14 | A | shading | axial `sh` inside a clip; shading-pattern fill | flagged non-flat; excluded from palette | shading |
| S15 | A | transparency | ExtGState `ca`/`CA` 0.5 overlap; image with `/SMask` | flagged; render-only | alpha |
| S16 | B | overprint | ExtGState `/OP true /op true /OPM 1` over CMYK fills | flagged; render behaviour `NEEDS-VERIFY` | print files |
| S17 | A | stroke-only area | closed 20 mm stroked loop; stroked line network ≥ 20 mm wide | area = buffer(width / 2); lines emitted as line features | stroke areas |
| S18 | A | clip stack | 3 nested clips; paths extend beyond them | visible polygon = clip intersection; truth carries the unclipped/visible area ratio | pre-clip overcount |
| S19 | A | art beyond trim | tiled texture past the trim | transform self-check `ok`; inside-share reported | self-check |
| S20 | A | speckle texture | flat base + seeded dots | segmentation returns the base region; palette = base colour via interior median, not mean | palette rule |
| S21 | B | foliage | thousands of tiny paths | not areas | texture |
| S22 | A | operator bytes in strings | literal strings containing ` l `, ` c `, ` re `, escaped `\)`; hex strings | operator census unaffected | predecessor regression |
| S23 | A | marked-content dict | `/Span <</MCID 0>> BDC … EMC` | `<<` consumed as a unit | predecessor regression |
| S24 | A | `m l l l h` vs `re` | same rect both ways | one painting op each; item counts differ | predecessor regression |
| S25 | B | nested Form XObjects | geometry 2 levels deep with `/Matrix` | paths-per-op ≈ 1; transform applied | completeness |
| S26 | B | hidden optional content | filled rect in a group that is OFF by default | not rendered; presence reported. Drawing-extraction behaviour `NEEDS-VERIFY` | layers |
| S27 | B | DeviceRGB mat | whole mat in RGB | source colour recorded as RGB, not forced to CMYK | colour model |
| S28 | B | ICCBased CMYK | N = 4 profile | deferred: needs a redistributable ICC profile | colour model |
| S29 | B | tiling pattern | area filled with a `/Pattern` | flagged non-flat | texture |
| S30 | B | mirrored raster | image placed with negative `d` in `cm` | fiducial test fails loudly; human gate | orientation |
| S31 | B | malformed / encrypted | truncated xref; owner-password encryption | clean error or reported repair; no crash | robustness |

## 5. Ground truth — `<case>.truth.json`

```json
{
  "case": "S01",
  "generator_version": "0.1.0",
  "seed": 0,
  "profile": {"nominal_mm": [2000.0, 1000.0], "tolerance_mm": 0.5},
  "boxes_pt": {"MediaBox": [0, 0, 5669.2913, 2834.6457], "TrimBox": [0, 0, 5669.2913, 2834.6457]},
  "expected": {"classification": "VECTOR", "frame_offset_mm": [0.0, 0.0], "hard_fail": null, "flags": []},
  "fiducial": {"polygon_mm": [[40, 40], [140, 40], [140, 60], [60, 60], [60, 140], [40, 140]], "dot_center_mm": [160, 150]},
  "regions": [
    {"truth_id": "r_flat_01", "kind": "area", "colorspace": "DeviceCMYK", "color": [0, 0, 1, 0],
     "outline_mm": [[1033, 517], [1244, 517], [1244, 706], [1033, 706]],
     "visible_polygon_mm": null, "area_mm2_exact": 39879.0, "border": null}
  ],
  "lines": [],
  "textures": [],
  "operators": {"painting_ops": 12, "clip_ops": 0, "decoy_strings": 0}
}
```

- `truth_id` is not the pipeline's `region_id`; tests match regions by IoU ≥ 0.99 (vector) /
  ≥ 0.95 (raster), then compare geometry.
- `visible_polygon_mm` is set whenever clipping or occlusion makes it differ from `outline_mm`.
- Values in the example are illustrative; real truth files are computed per G6.

## 6. Why S10 exists

Paths-per-painting-op measures **extraction completeness** — did MuPDF descend into every
painting operator? — not **vector-ness**. The predecessor toolchain used it correctly as a
completeness cross-check. A raster mat with a few vector crop marks scores 1.0 on the ratio, and
a raster-only mat has no painting operators at all (0 / 0). The classifier must use
**coverage**: the share of the trim area painted by vector fills versus by image placements,
and the placements' effective px/mm.

## 7. Assertion tolerances

| Quantity | Tolerance | Source |
|---|---|---|
| Vector-snapped geometry | ≤ 1e-3 mm | output precision (3 decimals) |
| Raster contour (S09) | ≤ ½ native px + ½ render px | sampling |
| Curved-area flattening error | reported, not asserted, until a flattening ADR sets a bound | G7 |
| Source colour | exact after documented quantisation | read from the content stream |
| Classification, flags, hard-fail | exact | — |

## 8. Interface

```python
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

CaseId = Literal["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10",
                 "S11", "S12", "S13", "S14", "S15", "S16", "S17", "S18", "S19", "S20",
                 "S21", "S22", "S23", "S24", "S25", "S26", "S27", "S28", "S29", "S30", "S31"]

@dataclass(frozen=True)
class MatProfile:
    nominal_mm: tuple[float, float]
    tolerance_mm: float = 0.5

@dataclass(frozen=True)
class GeneratedMat:
    case: CaseId
    seed: int
    profile: MatProfile
    pdf: bytes
    truth: dict[str, object]
    sha256: str

def generate(case: CaseId, profile: MatProfile, seed: int = 0) -> GeneratedMat: ...
def write(mat: GeneratedMat, out_dir: Path) -> tuple[Path, Path]: ...   # <case>.pdf, <case>.truth.json
```

CLI: `python scripts/gen_synthetic_mat.py --case S01 [--seed 0] [--profile FILE] --out DIR` ·
`--all` · `--check-manifest` (regenerate and compare with the committed sha256 manifest).

## 9. Acceptance criteria

- [ ] Two runs → identical bytes for every case, on amd64 and arm64.
- [ ] `qpdf --check` passes for S01–S30.
- [ ] `pdfminer.six` reads page boxes equal to `truth.boxes_pt` for every case.
- [ ] Every priority-A case has at least one pipeline test that fails if its expected behaviour regresses.
- [ ] The generator imports nothing outside the standard library.

## 10. Out of scope

Game objects · glyph or orientation markers beyond the fiducial · JPEG (`DCTDecode`) images.
