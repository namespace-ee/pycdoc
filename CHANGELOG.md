# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-09

### Added
- Initial release
- Python bindings for libcdoc using SWIG
- Support for reading and writing CDOC 1.0 and CDOC 2.0 containers
- High-level `encrypt()` function for encrypting files by Estonian personal ID code
- Automatic certificate lookup from SK LDAP (`esteid.ldap.sk.ee`)
- Support for encrypting single files, multiple files, or raw bytes
- Optional `ldap` extra for certificate lookup (`pip install pycdoc[ldap]`)
- `CDocReader` and `CDocWriter` classes
- Configuration classes: `Configuration`, `JSONConfiguration`
- Backend classes: `CryptoBackend`, `NetworkBackend`, `PKCS11Backend`
- Data types: `Recipient`, `Lock`, `FileInfo`, `DataSource`, `DataConsumer`
- Error codes and `get_error_str()` function
- Example scripts for creating CDOC containers
- CI/CD workflow with cibuildwheel for multi-platform builds
- macOS arm64 wheel support
