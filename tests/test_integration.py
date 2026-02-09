"""Integration tests for pycdoc - creating and reading CDOC files."""

import os
import tempfile
from unittest import mock
import pytest

# Skip all tests if cryptography is not installed
pytest.importorskip("cryptography")


def generate_test_certificate():
    """Generate a self-signed EC certificate for testing."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    private_key = ec.generate_private_key(ec.SECP384R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return cert_der, private_key_der


class TestCDocCreation:
    """Test creating CDOC files."""

    def test_create_cdoc2_with_certificate(self):
        """Test creating a CDOC 2.0 file with certificate-based encryption."""
        import pycdoc

        cert_der, _ = generate_test_certificate()

        with tempfile.NamedTemporaryFile(suffix=".cdoc", delete=False) as f:
            cdoc_path = f.name

        try:
            # Create writer
            writer = pycdoc.CDocWriter.createWriter(2, cdoc_path, None, None, None)
            assert writer is not None

            # Add recipient
            recipient = pycdoc.Recipient.makeCertificate("Test User", cert_der)
            assert recipient.isCertificate()
            result = writer.addRecipient(recipient)
            assert result == pycdoc.OK

            # Begin encryption
            result = writer.beginEncryption()
            assert result == pycdoc.OK

            # Add a file
            content = b"Hello, World! This is a secret message."
            result = writer.addFile("test.txt", len(content))
            assert result == pycdoc.OK

            result = writer.writeData(content)
            assert result == pycdoc.OK

            # Finish
            result = writer.finishEncryption()
            assert result == pycdoc.OK
            del writer

            # Verify file was created
            assert os.path.exists(cdoc_path)
            assert os.path.getsize(cdoc_path) > 0

        finally:
            if os.path.exists(cdoc_path):
                os.unlink(cdoc_path)

    def test_create_cdoc2_with_multiple_files(self):
        """Test creating a CDOC with multiple files."""
        import pycdoc

        cert_der, _ = generate_test_certificate()

        with tempfile.NamedTemporaryFile(suffix=".cdoc", delete=False) as f:
            cdoc_path = f.name

        try:
            writer = pycdoc.CDocWriter.createWriter(2, cdoc_path, None, None, None)
            recipient = pycdoc.Recipient.makeCertificate("Test User", cert_der)
            writer.addRecipient(recipient)
            writer.beginEncryption()

            # Add multiple files
            files = [
                ("file1.txt", b"Content of file 1"),
                ("file2.txt", b"Content of file 2"),
                ("data.bin", bytes(range(256))),
            ]

            for name, content in files:
                result = writer.addFile(name, len(content))
                assert result == pycdoc.OK
                result = writer.writeData(content)
                assert result == pycdoc.OK

            writer.finishEncryption()
            del writer

            assert os.path.getsize(cdoc_path) > 0

        finally:
            if os.path.exists(cdoc_path):
                os.unlink(cdoc_path)


class TestCDocReading:
    """Test reading CDOC files."""

    def test_read_cdoc_locks(self):
        """Test reading locks from a CDOC file."""
        import pycdoc

        cert_der, _ = generate_test_certificate()

        with tempfile.NamedTemporaryFile(suffix=".cdoc", delete=False) as f:
            cdoc_path = f.name

        try:
            # Create a CDOC file first
            writer = pycdoc.CDocWriter.createWriter(2, cdoc_path, None, None, None)
            recipient = pycdoc.Recipient.makeCertificate("Test Recipient", cert_der)
            writer.addRecipient(recipient)
            writer.beginEncryption()
            writer.addFile("test.txt", 5)
            writer.writeData(b"hello")
            writer.finishEncryption()
            del writer

            # Read it back
            reader = pycdoc.CDocReader.createReader(cdoc_path, None, None, None)
            assert reader is not None
            assert reader.version == 2

            # Get locks
            locks = reader.getLocks()
            assert len(locks) == 1

            del reader

        finally:
            if os.path.exists(cdoc_path):
                os.unlink(cdoc_path)

    def test_get_cdoc_version(self):
        """Test detecting CDOC file version."""
        import pycdoc

        cert_der, _ = generate_test_certificate()

        with tempfile.NamedTemporaryFile(suffix=".cdoc", delete=False) as f:
            cdoc_path = f.name

        try:
            # Create a CDOC 2 file
            writer = pycdoc.CDocWriter.createWriter(2, cdoc_path, None, None, None)
            recipient = pycdoc.Recipient.makeCertificate("Test", cert_der)
            writer.addRecipient(recipient)
            writer.beginEncryption()
            writer.addFile("test.txt", 4)
            writer.writeData(b"test")
            writer.finishEncryption()
            del writer

            # Check version detection
            version = pycdoc.CDocReader.getCDocFileVersion(cdoc_path)
            assert version == 2

        finally:
            if os.path.exists(cdoc_path):
                os.unlink(cdoc_path)


class TestEncryptFunction:
    """Test the high-level encrypt() function."""

    def _mock_fetch_certificate(self):
        """Return a mock that provides a test certificate."""
        cert_der, _ = generate_test_certificate()
        return cert_der, "Test User"

    def test_encrypt_file_to_bytes(self):
        """Test encrypting a file and getting bytes back."""
        import pycdoc

        # Create a test file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello, World!")
            input_path = f.name

        try:
            with mock.patch.object(
                pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
            ):
                result = pycdoc.encrypt(input_path, "38607080247")

            assert isinstance(result, bytes)
            assert len(result) > 0
            # CDOC2 files start with specific magic bytes
            assert result[:4] == b"CDOC"

        finally:
            os.unlink(input_path)

    def test_encrypt_file_to_output(self):
        """Test encrypting a file to an output path."""
        import pycdoc

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Secret content")
            input_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".cdoc", delete=False) as f:
            output_path = f.name

        try:
            with mock.patch.object(
                pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
            ):
                result = pycdoc.encrypt(input_path, "38607080247", output=output_path)

            assert result is None
            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 0

            # Verify it's a valid CDOC
            with open(output_path, "rb") as f:
                assert f.read(4) == b"CDOC"

        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_encrypt_raw_bytes(self):
        """Test encrypting raw bytes."""
        import pycdoc

        data = b"This is secret binary data"

        with mock.patch.object(
            pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
        ):
            result = pycdoc.encrypt(data, "38607080247", filename="secret.bin")

        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_encrypt_multiple_files(self):
        """Test encrypting multiple files."""
        import pycdoc

        # Create test files
        input_paths = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f"_{i}.txt", delete=False
            ) as f:
                f.write(f"Content of file {i}")
                input_paths.append(f.name)

        try:
            with mock.patch.object(
                pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
            ):
                result = pycdoc.encrypt(input_paths, "38607080247")

            assert isinstance(result, bytes)
            assert len(result) > 0

        finally:
            for path in input_paths:
                os.unlink(path)

    def test_encrypt_file_not_found(self):
        """Test that encrypting a non-existent file raises FileNotFoundError."""
        import pycdoc

        with mock.patch.object(
            pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
        ):
            with pytest.raises(FileNotFoundError):
                pycdoc.encrypt("/nonexistent/file.txt", "38607080247")

    def test_encrypt_invalid_data_type(self):
        """Test that encrypting invalid data type raises TypeError."""
        import pycdoc

        with mock.patch.object(
            pycdoc, "_fetch_certificate", return_value=self._mock_fetch_certificate()
        ):
            with pytest.raises(TypeError):
                pycdoc.encrypt(12345, "38607080247")  # type: ignore

    def test_encrypt_requires_ldap3(self):
        """Test that encrypt raises RuntimeError when ldap3 is not installed."""
        import pycdoc

        # Test the actual _fetch_certificate function without ldap3
        with mock.patch.dict("sys.modules", {"ldap3": None}):
            # Force re-import of the function logic
            with pytest.raises(RuntimeError, match="ldap3 package is required"):
                pycdoc._fetch_certificate("38607080247")
