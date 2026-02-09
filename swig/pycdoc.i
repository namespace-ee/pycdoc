/*
 * pycdoc - Python-specific SWIG interface for libcdoc
 *
 * This wraps the upstream libcdoc.i and adds Python-specific
 * template instantiations and director support.
 */

/* Enable directors for Python subclassing of C++ classes */
%feature("director") libcdoc::DataSource;
%feature("director") libcdoc::CryptoBackend;
%feature("director") libcdoc::PKCS11Backend;
%feature("director") libcdoc::NetworkBackend;
%feature("director") libcdoc::Configuration;
%feature("director") libcdoc::ILogger;

/* Include the upstream libcdoc SWIG interface */
%include "libcdoc.i"

/* Python-specific std::vector template instantiations */
%template(ByteVector) std::vector<uint8_t>;
%template(ByteVectorVector) std::vector<std::vector<uint8_t>>;
%template(StringVector) std::vector<std::string>;
