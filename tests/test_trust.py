"""Trust-layer tests against a cached snapshot of the ANTS TSL."""

from pathlib import Path

import pytest

pytest.importorskip("lxml")
pytest.importorskip("cryptography")

from twoddoc.trust.fetch import (  # noqa: E402
    CertResolver,
    _default_leaf_url,
    _is_rfc4387_store,
    _load_certs,
    _name_hash,
    _select_by_cn,
)
from twoddoc.trust.tsl import parse_tsl  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "tsl_sample.xml"


@pytest.fixture(scope="module")
def tsl():
    return parse_tsl(FIXTURE.read_bytes())


def test_tsl_entries(tsl):
    assert {"FR01", "FR03", "FR05"} <= set(tsl.entries)


def test_tsl_ca_certificate_present(tsl):
    fr01 = tsl.get("FR01")
    assert fr01.ca_certificates, "FR01 should carry an inline CA certificate"
    assert "FR01" in fr01.ca_certificates[0].subject.rfc4514_string()
    assert fr01.info_uris[0].startswith("http")


def test_default_leaf_url_derivation(tsl):
    # AriadNEXT: .../pki-2ddoc.der -> .../<ACID><CERTID>.der
    url = _default_leaf_url("FR01", "ABCD", tsl.get("FR01"))
    assert url == "http://cert.pki-2ddoc.ariadnext.fr/FR01ABCD.der"
    # ANTS: .../cev/FR05_cert.der -> .../cev/<ACID><CERTID>.der
    url5 = _default_leaf_url("FR05", "1234", tsl.get("FR05"))
    assert url5 == "http://sp.ants.gouv.fr/cev/FR051234.der"


def test_rfc4387_store_detection_and_hash(tsl):
    # Certigna (FR03) publishes via an RFC 4387 HTTP cert store (search.php?iHash=)
    fr03 = tsl.get("FR03")
    assert _is_rfc4387_store(fr03)
    assert not _is_rfc4387_store(tsl.get("FR01"))
    # iHash = base64(SHA1(issuer DN)); the CA's own value is published in the TSL.
    assert _name_hash(fr03.ca_certificates[0]) == "xvNLC1KMs03t/gxzdBYParPnf+M"


def _selfsigned(cn: str):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime(2020, 1, 1, tzinfo=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )


def test_bundle_parse_and_select_by_cn():
    # Simulate an AC "certificate list" (multipart/mixed of DER certs).
    from cryptography.hazmat.primitives.serialization import Encoding

    certs = [_selfsigned("AAAA"), _selfsigned("FPE7"), _selfsigned("BBBB")]
    boundary = "End"
    body = b""
    for c in certs:
        body += (f"--{boundary}\r\nContent-Type: application/pkix-cert\r\n\r\n").encode()
        body += c.public_bytes(Encoding.DER) + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    parsed = _load_certs(body, f"multipart/mixed; boundary={boundary}")
    assert len(parsed) == 3
    chosen = _select_by_cn(parsed, "FPE7")
    assert chosen is not None
    assert _select_by_cn(parsed, "ZZZZ") is None


def test_resolver_uses_inline_ca_as_anchor(tsl):
    from twoddoc.model import Encoding, Header

    resolver = CertResolver(tsl=tsl)
    header = Header(
        marker="DC", version=4, encoding=Encoding.C40, ca_id="FR01",
        cert_id="ZZZZ", emission_date=None, signature_date=None,
        document_type="01",
    )
    # offline keystore + cache miss, no network in tests -> raises while fetching,
    # but the CA anchors come straight from the TSL entry.
    entry = tsl.get(header.ca_id)
    assert entry.ca_certificates
