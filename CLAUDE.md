# pycdoc

Python bindings for [libcdoc](https://github.com/open-eid/libcdoc) via SWIG. Produces installable wheels for reading and writing encrypted CDOC containers.

## Architecture

- `libcdoc/` — upstream C++ library as a git submodule
- `patches/libcdoc-python.patch` — adds Python typemaps, templates, and director support to upstream `libcdoc.i`
- `CMakeLists.txt` — applies patch, builds upstream statically, then builds SWIG Python module
- `swig/pycdoc.i` — thin wrapper: `%rename` for snake_case + `%include "libcdoc.i"`
- `src/pycdoc/__init__.py` — re-exports SWIG symbols, provides high-level `encrypt()` API

## Key decisions

- **Static linking** (`BUILD_SHARED_LIBS=OFF`) — self-contained wheels, LGPL-2.1 compliance via RELINKING.md + sdist source
- **Patch-based approach** — upstream libcdoc.i is modified via `patches/libcdoc-python.patch` at CMake configure time (rather than forking)
- **SWIG `%rename` before `%include`** — order matters, rename rules must appear before upstream interface is included

## Test

```bash
uv sync --dev
uv run pytest tests/ -v
```

## Build

```bash
# System deps (Ubuntu): libssl-dev libxml2-dev zlib1g-dev flatbuffers-compiler libflatbuffers-dev
uv build --wheel
```

Uses scikit-build-core as the build backend bridging CMake. Requires C++23, SWIG 4.0+, CMake 3.20+.

## Git

Never use `git -C <path>` — always run git commands from the working directory.

## CI

`.github/workflows/build.yml` — 5 jobs:
1. `build` — every push, Ubuntu only (quick feedback)
2. `test` — runs pytest against the built wheel
3. `build_wheels` — on release/PR, cibuildwheel v3.3.1 across Linux/macOS/Windows
4. `build_sdist` — on release/PR
5. `publish` — OIDC trusted publishing to PyPI

Linux wheels build OpenSSL 3.5 LTS and flatbuffers from source inside manylinux_2_28 with GCC 13.

## Version management

`bump-my-version` configured in pyproject.toml. Updates version in pyproject.toml, `__init__.py`, and CMakeLists.txt, commits, and tags.
