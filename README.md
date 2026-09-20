# matsurvey

Survey robot-competition mats: import a mat PDF you supply into mm-exact geometry you can
measure, snap and simulate. Self-hosted.

> matsurvey is an independent project. It is not affiliated with, endorsed by, or sponsored
> by any competition organiser, manufacturer or other third party. It ships no third-party
> mats, documents, artwork or rules. All trademarks belong to their respective owners.

**Status:** pre-alpha. Nothing is released yet.

## What it will do

| You get | How |
|---|---|
| Distances, angles, turn angles, distance to walls, wheel rotations | viewer |
| Snapping to line edges, area corners and centroids, exact to the vector artwork | semantic layer |
| Robot footprint overlay with heading and turn sweep | viewer |
| Route export for robot code and a geometry file for your own simulator | export |

## Bring your own PDF

This repository contains no competition content and never will: no mat files, no renders,
no geometry derived from a mat, no rules text. You obtain the mat PDF yourself; matsurvey
processes it on your machine.

## Contributing

Run `python scripts/install_hooks.py` after cloning. Every commit, push and pull request is
checked by the content guard; the check cannot be bypassed. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under AGPL-3.0-or-later — see [LICENSE](LICENSE). Third-party components and their
licenses are listed in [NOTICE](NOTICE). matsurvey uses PyMuPDF, which is available under the
GNU AGPL or a commercial license from Artifex.
