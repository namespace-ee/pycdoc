# pycdoc

Python bindings for [libcdoc](https://github.com/open-eid/libcdoc) - a library for reading and writing encrypted CDOC containers.

CDOC is a file format for encrypting documents, used primarily in Estonia for secure document exchange with the Estonian ID-card ecosystem.

## Installation

```bash
uv add pycdoc
```

## Requirements

### Runtime
- Python 3.10+
- OpenSSL 3.0+ (usually pre-installed on modern systems)

### Building from Source

Building from source requires:
- Python 3.10+
- CMake 3.20+
- SWIG 4.0+
- OpenSSL 3.0+
- libxml2
- zlib
- FlatBuffers
- C++23 compatible compiler

**macOS:**
```bash
brew install cmake swig openssl@3 libxml2 flatbuffers
```

**Ubuntu/Debian:**
```bash
sudo apt install cmake swig libssl-dev libxml2-dev zlib1g-dev libflatbuffers-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install cmake swig openssl-devel libxml2-devel zlib-devel flatbuffers-devel
```

## Quick Start

Install with LDAP support for certificate lookup:

```bash
uv add "pycdoc[ldap]"
```

### Encrypting Files

```python
import pycdoc

# Encrypt a file for an Estonian ID card holder
pycdoc.encrypt("document.pdf", "38607080247", output="encrypted.cdoc")

# Get CDOC as bytes instead of writing to file
cdoc_bytes = pycdoc.encrypt("document.pdf", "38607080247")

# Encrypt raw bytes
pycdoc.encrypt(b"secret content", "38607080247", filename="secret.txt", output="encrypted.cdoc")

# Encrypt multiple files into one container
pycdoc.encrypt(["file1.pdf", "file2.docx"], "38607080247", output="bundle.cdoc")
```

The recipient can decrypt with [DigiDoc4 Client](https://www.id.ee/en/article/install-id-software/) or `cdoc-tool`.

## API Overview

### Core Classes

- `CDocReader` - Read and decrypt CDOC containers
- `CDocWriter` - Create and encrypt CDOC containers

### Configuration

- `Configuration` - Base configuration class (can be subclassed)
- `JSONConfiguration` - JSON file-based configuration

### Backends

- `CryptoBackend` - Cryptographic operations backend (can be subclassed)
- `NetworkBackend` - Network operations backend for key servers
- `PKCS11Backend` - PKCS#11 hardware token backend (smart cards, HSMs)

### Data Types

- `Recipient` - Encryption recipient information
- `Lock` - Decryption lock information
- `FileInfo` - File metadata (name, size)
- `DataSource` - Abstract data source for streaming
- `DataConsumer` - Abstract data consumer for streaming

### Result Codes

- `OK` - Operation successful
- `WRONG_KEY` - Incorrect decryption key
- `DATA_FORMAT_ERROR` - Invalid container format
- `CRYPTO_ERROR` - Cryptographic operation failed
- `PKCS11_ERROR` - PKCS#11/smart card error

Use `pycdoc.get_error_str(code)` to get human-readable error descriptions.

## Building from Source

1. Clone the repository with submodules:
```bash
git clone --recurse-submodules https://github.com/namespace-ee/pycdoc.git
cd pycdoc
```

2. Build the wheel:
```bash
uv build --wheel
```

3. Install the wheel:
```bash
uv pip install dist/pycdoc-*.whl
```

## Development

```bash
# Build wheel
uv build --wheel

# Install in development mode (rebuild required after changes)
uv pip install --force-reinstall dist/pycdoc-*.whl

# Run tests
uv run pytest tests/ -v
```

## License

This library is licensed under the GNU Lesser General Public License v2.1 or later (LGPL-2.1-or-later).

See [LICENSE](LICENSE) for the full license text.

## Links

- [libcdoc repository](https://github.com/open-eid/libcdoc)
- [Estonian ID software](https://www.id.ee/)
- [CDOC 2.0 specification](https://github.com/open-eid/cdoc2-spec)
