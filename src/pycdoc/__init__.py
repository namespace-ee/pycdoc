"""
pycdoc - Python bindings for libcdoc

A library for reading and writing encrypted CDOC containers.
"""

from __future__ import annotations

import os

from pycdoc.libcdoc import (
    # Version and utilities
    get_version,
    get_error_str,

    # Result codes
    OK,
    END_OF_STREAM,
    NOT_IMPLEMENTED,
    NOT_SUPPORTED,
    WRONG_ARGUMENTS,
    WORKFLOW_ERROR,
    IO_ERROR,
    OUTPUT_ERROR,
    OUTPUT_STREAM_ERROR,
    INPUT_ERROR,
    INPUT_STREAM_ERROR,
    WRONG_KEY,
    DATA_FORMAT_ERROR,
    CRYPTO_ERROR,
    ZLIB_ERROR,
    PKCS11_ERROR,
    HASH_MISMATCH,
    CONFIGURATION_ERROR,
    NOT_FOUND,
    UNSPECIFIED_ERROR,

    # Core classes
    CDocReader,
    CDocWriter,

    # Configuration
    Configuration,
    JSONConfiguration,

    # Backends
    CryptoBackend,
    NetworkBackend,
    PKCS11Backend,

    # Data types
    Recipient,
    Lock,
    FileInfo,
    DataBuffer,
    DataSource,
    DataConsumer,

    # Container types
    ByteVector,
    ByteVectorVector,
    StringVector,
    LockVector,
    CertificateList,

    # Logging
    Logger,
)

__version__ = "0.1.1"

# LDAP server for Estonian ID card certificates
_SK_LDAP_SERVER = "esteid.ldap.sk.ee"
_SK_LDAP_BASE_DN = "c=EE"


def _fetch_certificate(personal_code: str) -> tuple[bytes, str]:
    """Fetch authentication certificate from SK LDAP by personal ID code.

    Args:
        personal_code: Estonian personal ID code (isikukood)

    Returns:
        Tuple of (certificate_der_bytes, common_name)

    Raises:
        RuntimeError: If ldap3 is not installed or certificate not found
    """
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except ImportError:
        raise RuntimeError(
            "ldap3 package is required for certificate lookup. "
            "Install with: pip install pycdoc[ldap]"
        )

    server = Server(_SK_LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)

    # Search for authentication certificate by serial number (personal code)
    # The serialNumber attribute contains the personal ID code
    search_filter = f"(serialNumber=PNOEE-{personal_code})"

    conn.search(
        search_base=_SK_LDAP_BASE_DN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["userCertificate;binary", "cn"],
    )

    if not conn.entries:
        raise RuntimeError(f"No certificate found for personal code: {personal_code}")

    # Find the authentication certificate (not the signing certificate)
    for entry in conn.entries:
        if hasattr(entry, "userCertificate;binary"):
            cert_attr = getattr(entry, "userCertificate;binary")
            if cert_attr.value:
                cert_der = bytes(cert_attr.value)
                cn = entry.cn.value if hasattr(entry, "cn") else "Unknown"
                conn.unbind()
                return cert_der, cn

    conn.unbind()
    raise RuntimeError(f"No certificate found for personal code: {personal_code}")


def encrypt(
    data: "Union[str, bytes, list[str]]",
    personal_code: str,
    *,
    output: "Union[str, None]" = None,
    filename: str = "data.bin",
) -> "Union[bytes, None]":
    """Encrypt file(s) for an Estonian ID card holder.

    Args:
        data: File path, list of file paths, or raw bytes to encrypt
        personal_code: Estonian personal ID code (isikukood)
        output: Output file path. If None, returns CDOC as bytes
        filename: Filename to use when encrypting raw bytes

    Returns:
        CDOC file contents as bytes if output is None, otherwise None

    Raises:
        RuntimeError: If encryption fails or certificate not found
        FileNotFoundError: If input file does not exist

    Example:
        # Encrypt a file
        pycdoc.encrypt("document.pdf", "38607080247", output="encrypted.cdoc")

        # Get CDOC as bytes
        cdoc_bytes = pycdoc.encrypt("document.pdf", "38607080247")

        # Encrypt raw bytes
        pycdoc.encrypt(b"secret content", "38607080247", filename="secret.txt")

        # Encrypt multiple files
        pycdoc.encrypt(["file1.pdf", "file2.docx"], "38607080247", output="bundle.cdoc")
    """
    import tempfile

    # Fetch recipient certificate from LDAP
    cert_der, cn = _fetch_certificate(personal_code)

    # Determine output path
    if output is None:
        # Create a temporary file to write to, then read back
        temp_fd, temp_path = tempfile.mkstemp(suffix=".cdoc")
        os.close(temp_fd)
        output_path = temp_path
        return_bytes = True
    else:
        output_path = output
        return_bytes = False

    try:
        # Create CDOC 2.0 writer
        writer = CDocWriter.create_writer(2, output_path, None, None, None)
        if writer is None:
            raise RuntimeError("Failed to create CDOC writer")

        # Add recipient
        recipient = Recipient.make_certificate(cn, cert_der)
        result = writer.add_recipient(recipient)
        if result != OK:
            raise RuntimeError(f"Failed to add recipient: {get_error_str(result)}")

        # Begin encryption
        result = writer.begin_encryption()
        if result != OK:
            raise RuntimeError(f"Failed to begin encryption: {get_error_str(result)}")

        # Prepare files to encrypt
        if isinstance(data, bytes):
            # Raw bytes
            files_to_write = [(filename, data)]
        elif isinstance(data, str):
            # Single file path
            if not os.path.exists(data):
                raise FileNotFoundError(f"File not found: {data}")
            with open(data, "rb") as f:
                content = f.read()
            files_to_write = [(os.path.basename(data), content)]
        elif isinstance(data, list):
            # Multiple file paths
            files_to_write = []
            for file_path in data:
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"File not found: {file_path}")
                with open(file_path, "rb") as f:
                    content = f.read()
                files_to_write.append((os.path.basename(file_path), content))
        else:
            raise TypeError(f"data must be str, bytes, or list[str], not {type(data).__name__}")

        # Write files
        for name, content in files_to_write:
            result = writer.add_file(name, len(content))
            if result != OK:
                raise RuntimeError(f"Failed to add file {name}: {get_error_str(result)}")
            result = writer.write_data(content)
            if result != OK:
                raise RuntimeError(f"Failed to write data for {name}: {get_error_str(result)}")

        # Finish encryption
        result = writer.finish_encryption()
        if result != OK:
            raise RuntimeError(f"Failed to finish encryption: {get_error_str(result)}")

        # Clean up writer
        del writer

        if return_bytes:
            with open(output_path, "rb") as f:
                cdoc_bytes = f.read()
            return cdoc_bytes
        else:
            return None

    finally:
        # Clean up temp file if we created one
        if return_bytes and os.path.exists(output_path):
            os.unlink(output_path)


__all__ = [
    # High-level API
    "encrypt",

    # Version
    "__version__",
    "get_version",
    "get_error_str",

    # Result codes
    "OK",
    "END_OF_STREAM",
    "NOT_IMPLEMENTED",
    "NOT_SUPPORTED",
    "WRONG_ARGUMENTS",
    "WORKFLOW_ERROR",
    "IO_ERROR",
    "OUTPUT_ERROR",
    "OUTPUT_STREAM_ERROR",
    "INPUT_ERROR",
    "INPUT_STREAM_ERROR",
    "WRONG_KEY",
    "DATA_FORMAT_ERROR",
    "CRYPTO_ERROR",
    "ZLIB_ERROR",
    "PKCS11_ERROR",
    "HASH_MISMATCH",
    "CONFIGURATION_ERROR",
    "NOT_FOUND",
    "UNSPECIFIED_ERROR",

    # Core classes
    "CDocReader",
    "CDocWriter",

    # Configuration
    "Configuration",
    "JSONConfiguration",

    # Backends
    "CryptoBackend",
    "NetworkBackend",
    "PKCS11Backend",

    # Data types
    "Recipient",
    "Lock",
    "FileInfo",
    "DataBuffer",
    "DataSource",
    "DataConsumer",

    # Container types
    "ByteVector",
    "ByteVectorVector",
    "StringVector",
    "LockVector",
    "CertificateList",

    # Logging
    "Logger",
]
