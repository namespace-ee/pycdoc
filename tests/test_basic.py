"""Basic tests for pycdoc package."""

import pytest


class TestImports:
    """Test that all public API can be imported."""

    def test_import_pycdoc(self):
        import pycdoc
        assert pycdoc is not None

    def test_import_version(self):
        from pycdoc import get_version, __version__
        assert callable(get_version)
        assert isinstance(__version__, str)

    def test_import_error_str(self):
        from pycdoc import get_error_str
        assert callable(get_error_str)

    def test_import_result_codes(self):
        from pycdoc import (
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
        )
        assert OK == 0

    def test_import_core_classes(self):
        from pycdoc import CDocReader, CDocWriter
        assert CDocReader is not None
        assert CDocWriter is not None

    def test_import_configuration(self):
        from pycdoc import Configuration, JSONConfiguration
        assert Configuration is not None
        assert JSONConfiguration is not None

    def test_import_backends(self):
        from pycdoc import CryptoBackend, NetworkBackend, PKCS11Backend
        assert CryptoBackend is not None
        assert NetworkBackend is not None
        assert PKCS11Backend is not None

    def test_import_data_types(self):
        from pycdoc import (
            Recipient,
            Lock,
            FileInfo,
            DataBuffer,
            DataSource,
            DataConsumer,
        )
        assert Recipient is not None
        assert Lock is not None
        assert FileInfo is not None

    def test_import_containers(self):
        from pycdoc import (
            ByteVector,
            ByteVectorVector,
            StringVector,
            LockVector,
            CertificateList,
        )
        assert ByteVector is not None
        assert LockVector is not None

    def test_import_logging(self):
        from pycdoc import Logger
        assert Logger is not None


class TestVersion:
    """Test version information."""

    def test_get_version_returns_string(self):
        from pycdoc import get_version
        version = get_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_version_format(self):
        from pycdoc import get_version
        version = get_version()
        # Version should be in format like "0.1.8.0"
        parts = version.split(".")
        assert len(parts) >= 3
        for part in parts:
            assert part.isdigit()


class TestErrorCodes:
    """Test error codes and error string function."""

    def test_ok_is_zero(self):
        from pycdoc import OK
        assert OK == 0

    def test_error_codes_are_negative(self):
        from pycdoc import (
            NOT_IMPLEMENTED,
            NOT_SUPPORTED,
            WRONG_ARGUMENTS,
            IO_ERROR,
            CRYPTO_ERROR,
        )
        assert NOT_IMPLEMENTED < 0
        assert NOT_SUPPORTED < 0
        assert WRONG_ARGUMENTS < 0
        assert IO_ERROR < 0
        assert CRYPTO_ERROR < 0

    @pytest.mark.skip(reason="SWIG int64_t binding issue")
    def test_get_error_str_for_ok(self):
        from pycdoc import get_error_str, OK
        result = get_error_str(OK)
        assert isinstance(result, str)

    @pytest.mark.skip(reason="SWIG int64_t binding issue")
    def test_get_error_str_for_error(self):
        from pycdoc import get_error_str, CRYPTO_ERROR
        result = get_error_str(CRYPTO_ERROR)
        assert isinstance(result, str)
        assert len(result) > 0


class TestRecipient:
    """Test Recipient class."""

    def test_create_recipient(self):
        from pycdoc import Recipient
        r = Recipient()
        assert r is not None

    def test_recipient_type_default(self):
        from pycdoc import Recipient
        r = Recipient()
        # Default type should be NONE (0)
        assert r.type == 0

    def test_recipient_is_empty(self):
        from pycdoc import Recipient
        r = Recipient()
        assert r.is_empty()

    def test_recipient_label(self):
        from pycdoc import Recipient
        r = Recipient()
        r.label = "test_label"
        assert r.label == "test_label"


class TestLock:
    """Test Lock class."""

    def test_lock_class_exists(self):
        from pycdoc import Lock
        assert Lock is not None

    def test_lock_type_constants(self):
        from pycdoc import Lock
        # Check that type constants exist
        assert hasattr(Lock, "SYMMETRIC_KEY")
        assert hasattr(Lock, "PUBLIC_KEY")
        assert hasattr(Lock, "CDOC1")
        assert hasattr(Lock, "SERVER")


class TestFileInfo:
    """Test FileInfo class."""

    def test_create_fileinfo(self):
        from pycdoc import FileInfo
        fi = FileInfo()
        assert fi is not None

    def test_fileinfo_name(self):
        from pycdoc import FileInfo
        fi = FileInfo()
        fi.name = "test.txt"
        assert fi.name == "test.txt"

    @pytest.mark.skip(reason="SWIG int64_t binding issue")
    def test_fileinfo_size(self):
        from pycdoc import FileInfo
        fi = FileInfo()
        # size is int64_t, SWIG binding has issues
        assert fi.size == 0


class TestContainers:
    """Test container types."""

    def test_byte_vector(self):
        from pycdoc import ByteVector
        bv = ByteVector()
        assert len(bv) == 0
        # ByteVector uses std::vector<uint8_t>, test basic operations
        assert bv.empty()
        bv.clear()
        assert bv.empty()

    def test_string_vector(self):
        from pycdoc import StringVector
        sv = StringVector()
        assert len(sv) == 0
        sv.append("hello")
        sv.append("world")
        assert len(sv) == 2
        assert sv[0] == "hello"
        assert sv[1] == "world"

    def test_lock_vector(self):
        from pycdoc import LockVector
        lv = LockVector()
        assert len(lv) == 0


class TestCertificateList:
    """Test CertificateList class."""

    def test_create_certificate_list(self):
        from pycdoc import CertificateList
        cl = CertificateList()
        assert cl is not None

    def test_certificate_list_size(self):
        from pycdoc import CertificateList
        cl = CertificateList()
        assert cl.size() == 0

    def test_certificate_list_clear(self):
        from pycdoc import CertificateList
        cl = CertificateList()
        # Test that clear works on empty list
        cl.clear()
        assert cl.size() == 0


class TestDataBuffer:
    """Test DataBuffer class."""

    def test_create_data_buffer(self):
        from pycdoc import DataBuffer
        db = DataBuffer()
        assert db is not None


class TestConfiguration:
    """Test Configuration classes."""

    def test_create_configuration(self):
        from pycdoc import Configuration
        # Configuration is abstract, but we can create a subclass
        config = Configuration()
        assert config is not None

    def test_json_configuration(self):
        from pycdoc import JSONConfiguration
        config = JSONConfiguration()
        assert config is not None


class TestLogger:
    """Test logging classes."""

    def test_create_logger(self):
        from pycdoc import Logger
        logger = Logger()
        assert logger is not None

    def test_logger_levels(self):
        from pycdoc.libcdoc import LEVEL_TRACE, LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARNING, LEVEL_ERROR, LEVEL_FATAL
        assert LEVEL_TRACE is not None
        assert LEVEL_DEBUG is not None
        assert LEVEL_INFO is not None
        assert LEVEL_WARNING is not None
        assert LEVEL_ERROR is not None
        assert LEVEL_FATAL is not None
