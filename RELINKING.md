# Relinking Instructions (LGPL-2.1 Compliance)

pycdoc statically links libcdoc into the Python extension module. Under LGPL-2.1
Section 6, you have the right to modify libcdoc and relink. Here's how.

## Prerequisites

- Python 3.10+
- CMake 3.20+
- C++23 compiler (GCC 13+, Clang 16+, MSVC 2022+)
- SWIG 4.0+
- System libraries: OpenSSL 3.0+, libxml2, zlib, flatbuffers

## Rebuilding from source distribution

```bash
# Install the sdist (includes libcdoc source via git submodule)
pip download --no-binary pycdoc pycdoc
tar xzf pycdoc-*.tar.gz
cd pycdoc-*/

# Modify libcdoc/ as needed
# ...

# Build a new wheel
pip install scikit-build-core swig
python -m build --wheel
pip install dist/*.whl
```

## Rebuilding from the git repository

```bash
git clone --recurse-submodules https://github.com/namespace-ee/pycdoc.git
cd pycdoc

# Modify libcdoc/ as needed
# ...

# Build
pip install scikit-build-core swig
python -m build --wheel
pip install dist/*.whl
```
