#!/usr/bin/env python3
"""Example: Create an encrypted CDOC 2.0 file with certificate-based encryption."""

import os
import pycdoc

# Generate a self-signed certificate for testing
# In production, you would use a real certificate (e.g., from Estonian ID-card)
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
    return cert.public_bytes(serialization.Encoding.DER)


def main():
    print(f"pycdoc version: {pycdoc.get_version()}")
    print()

    # Generate a test certificate
    print("Generating test certificate...")
    cert_der = generate_test_certificate()
    print(f"  Certificate size: {len(cert_der)} bytes")

    # Create output file
    output_file = "example.cdoc"

    # Create the CDOC writer
    print(f"\nCreating CDOC file: {output_file}")
    writer = pycdoc.CDocWriter.createWriter(2, output_file, None, None, None)
    if writer is None:
        print("ERROR: Failed to create writer")
        return 1

    # Add recipient (the certificate holder can decrypt)
    recipient = pycdoc.Recipient.makeCertificate("Test User", cert_der)
    result = writer.addRecipient(recipient)
    if result != pycdoc.OK:
        print(f"ERROR: addRecipient failed: {result}")
        return 1
    print("  Added recipient: Test User")

    # Begin encryption
    result = writer.beginEncryption()
    if result != pycdoc.OK:
        print(f"ERROR: beginEncryption failed: {result}")
        return 1

    # Add files to the container
    files = [
        ("hello.txt", b"Hello, World! This is a secret message."),
        ("data.txt", b"Some confidential data that needs protection."),
    ]

    for filename, content in files:
        result = writer.addFile(filename, len(content))
        if result != pycdoc.OK:
            print(f"ERROR: addFile failed for {filename}: {result}")
            return 1

        result = writer.writeData(content)
        if result != pycdoc.OK:
            print(f"ERROR: writeData failed for {filename}: {result}")
            return 1

        print(f"  Added file: {filename} ({len(content)} bytes)")

    # Finish encryption
    result = writer.finishEncryption()
    if result != pycdoc.OK:
        print(f"ERROR: finishEncryption failed: {result}")
        return 1

    # Clean up writer
    del writer

    # Verify the file was created
    file_size = os.path.getsize(output_file)
    print(f"\nCreated: {output_file} ({file_size} bytes)")

    # Read back the CDOC to verify
    print("\nReading CDOC file...")
    reader = pycdoc.CDocReader.createReader(output_file, None, None, None)
    if reader is None:
        print("ERROR: Failed to create reader")
        return 1

    print(f"  CDOC version: {reader.version}")

    locks = reader.getLocks()
    print(f"  Recipients: {len(locks)}")
    for i, lock in enumerate(locks):
        print(f"    [{i}] {lock.label}")

    del reader

    print("\nSuccess! The CDOC file was created and verified.")
    print(f"Note: To decrypt, you would need the private key for the certificate.")

    return 0


if __name__ == "__main__":
    exit(main())
