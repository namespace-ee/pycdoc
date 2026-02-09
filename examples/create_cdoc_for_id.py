#!/usr/bin/env python3
"""Create a CDOC 2.0 file encrypted for an Estonian ID card holder.

Usage:
    # With certificate file (PEM or DER format):
    python create_cdoc_for_id.py --cert certificate.cer

    # Fetch from SK LDAP (may not work on all networks):
    python create_cdoc_for_id.py --id 38607080247

To get a certificate manually:
    1. Visit https://www.sk.ee/en/repository/certs/
    2. Or use: ldapsearch -x -H ldap://esteid.ldap.sk.ee -b "c=EE" "(serialNumber=PNOEE-38607080247)"
"""

import argparse
import os
import sys
import pycdoc


def load_certificate_from_file(cert_path: str) -> tuple[bytes, str]:
    """Load certificate from PEM or DER file."""
    with open(cert_path, "rb") as f:
        data = f.read()

    # Check if PEM format
    if b"-----BEGIN CERTIFICATE-----" in data:
        import base64
        # Extract base64 content
        pem_lines = data.decode("utf-8").split("\n")
        b64_lines = [l for l in pem_lines if not l.startswith("-----") and l.strip()]
        cert_der = base64.b64decode("".join(b64_lines))
    else:
        cert_der = data

    # Extract CN from certificate
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(cert_der)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = os.path.basename(cert_path)

    return cert_der, cn


def fetch_certificate_from_ldap(personal_id: str) -> tuple[bytes, str]:
    """Fetch authentication certificate from Estonian SK LDAP."""
    try:
        from ldap3 import Server, Connection, Tls
    except ImportError:
        raise RuntimeError("ldap3 not installed. Run: pip install ldap3")

    import ssl

    print("  Connecting to esteid.ldap.sk.ee (LDAPS)...")

    # Use LDAPS with TLS 1.2
    tls = Tls(
        validate=ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLSv1_2,
        ciphers='DEFAULT:@SECLEVEL=1'
    )
    server = Server("esteid.ldap.sk.ee", port=636, use_ssl=True, tls=tls, connect_timeout=15)
    conn = Connection(server, auto_bind=True, receive_timeout=15)

    search_filter = f"(serialNumber=PNOEE-{personal_id})"
    conn.search(
        search_base="c=EE",
        search_filter=search_filter,
        attributes=["userCertificate;binary", "cn"],
    )

    cert_der = None
    cn = None

    for entry in conn.entries:
        dn = str(entry.entry_dn)
        if "ou=Authentication" in dn:
            cert_attr = entry["userCertificate;binary"]
            # Handle both single value and list
            cert_values = cert_attr.values if hasattr(cert_attr, 'values') else [cert_attr.value]
            cert_der = cert_values[0] if isinstance(cert_values, list) else cert_values
            cn = str(entry.cn) if hasattr(entry, "cn") else None
            break

    conn.unbind()

    if cert_der is None:
        raise RuntimeError(f"No authentication certificate found for {personal_id}")

    return cert_der, cn or personal_id


def create_cdoc(cert_der: bytes, cn: str, output_file: str, files: list[tuple[str, bytes]]):
    """Create a CDOC 2.0 file."""
    print(f"\nCreating CDOC file: {output_file}")
    writer = pycdoc.CDocWriter.createWriter(2, output_file, None, None, None)
    if writer is None:
        raise RuntimeError("Failed to create writer")

    recipient = pycdoc.Recipient.makeCertificate(cn, cert_der)
    result = writer.addRecipient(recipient)
    if result != pycdoc.OK:
        raise RuntimeError(f"addRecipient failed: {result}")
    print(f"  Recipient: {cn}")

    result = writer.beginEncryption()
    if result != pycdoc.OK:
        raise RuntimeError(f"beginEncryption failed: {result}")

    for filename, content in files:
        result = writer.addFile(filename, len(content))
        if result != pycdoc.OK:
            raise RuntimeError(f"addFile failed for {filename}: {result}")
        result = writer.writeData(content)
        if result != pycdoc.OK:
            raise RuntimeError(f"writeData failed for {filename}: {result}")
        print(f"  Added: {filename} ({len(content)} bytes)")

    result = writer.finishEncryption()
    if result != pycdoc.OK:
        raise RuntimeError(f"finishEncryption failed: {result}")

    del writer
    return os.path.getsize(output_file)


def main():
    parser = argparse.ArgumentParser(description="Create CDOC for Estonian ID card holder")
    parser.add_argument("--cert", "-c", help="Path to certificate file (PEM or DER)")
    parser.add_argument("--id", "-i", dest="personal_id", help="Personal ID code (isikukood)")
    parser.add_argument("--output", "-o", default="encrypted.cdoc", help="Output CDOC file")
    parser.add_argument("files", nargs="*", help="Files to encrypt (default: creates test file)")
    args = parser.parse_args()

    if not args.cert and not args.personal_id:
        parser.error("Either --cert or --id is required")

    print(f"pycdoc version: {pycdoc.get_version()}\n")

    # Get certificate
    if args.cert:
        print(f"Loading certificate from: {args.cert}")
        cert_der, cn = load_certificate_from_file(args.cert)
    else:
        print(f"Fetching certificate for: {args.personal_id}")
        cert_der, cn = fetch_certificate_from_ldap(args.personal_id)

    print(f"  Certificate: {cn} ({len(cert_der)} bytes)")

    # Prepare files
    if args.files:
        files = []
        for path in args.files:
            with open(path, "rb") as f:
                files.append((os.path.basename(path), f.read()))
    else:
        files = [("secret_message.txt", b"Hello! This is a secret message.\n\nDecrypt with DigiDoc4 or cdoc-tool.")]

    # Create CDOC
    size = create_cdoc(cert_der, cn, args.output, files)
    print(f"\nCreated: {args.output} ({size} bytes)")

    # Verify
    reader = pycdoc.CDocReader.createReader(args.output, None, None, None)
    if reader:
        print(f"\nVerified: CDOC {reader.version} with {len(reader.getLocks())} recipient(s)")
        del reader

    print("\nDecrypt with: DigiDoc4 Client or cdoc-tool decrypt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
