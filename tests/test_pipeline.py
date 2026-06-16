"""Offline full-pipeline test: decode -> resolve (keystore) -> verify signature."""

from pathlib import Path

import pytest

pytest.importorskip("lxml")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

from twoddoc.reader import decode  # noqa: E402
from twoddoc.trust.fetch import CertResolver  # noqa: E402
from twoddoc.trust.tsl import parse_tsl  # noqa: E402
from twoddoc.trust.verify import verify  # noqa: E402
from tests.test_reference_v4 import REF_CERT_PEM, _ex2_payload  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "tsl_sample.xml"


def test_verify_via_resolver_and_keystore(tmp_path):
    # keystore holding the reference leaf certificate as <ACID><CERTID>.der
    cert = x509.load_pem_x509_certificate(REF_CERT_PEM)
    keystore = tmp_path / "certs"
    keystore.mkdir()
    (keystore / "FR000001.der").write_bytes(cert.public_bytes(Encoding.DER))

    doc = decode(_ex2_payload())
    resolver = CertResolver(
        tsl=parse_tsl(FIXTURE.read_bytes()),
        keystore_dir=keystore,
        cache_dir=tmp_path / "cache",
    )
    leaf, anchors = resolver.resolve(doc.header)
    assert leaf.subject.rfc4514_string() == cert.subject.rfc4514_string()

    result = verify(doc, leaf, anchors, check_revocation=False)
    # the real reference signature verifies over the reconstructed data zone
    assert result.signature_valid is True
    # FR00 is a test AC absent from the production TSL -> no chain anchor
    assert any("trust anchor" in e for e in result.errors)
