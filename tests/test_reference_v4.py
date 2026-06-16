"""End-to-end tests against the official reference codes & certificate (§16).

Both reference codes are signed with the test certificate (NIST P-256, CA FR00,
cert 0001).

* **Example 1** (Acte d'huissier, doc type 12) exercises header/field parsing and
  the signed-data reconstruction: the encoded data zone omits a ``<GS>`` at the
  mandatory→facultatif boundary after the fixed field ``96``.
* **Example 2** (Attestation CVE, doc type B1) has no internal spaces in its
  values, so its exact signed bytes are unambiguous — we verify the real ECDSA
  signature against it end-to-end.
"""

from datetime import date

import pytest

from twoddoc.codecs import base32
from twoddoc.message import GS, US
from twoddoc.reader import decode

pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402

REF_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIICVzCCAT8CCQCpMEvcR9M4RTANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJG
UjETMBEGA1UECgwKQUMgREUgVEVTVDEcMBoGA1UECwwTMDAwMiAwMDAwMDAwMDAw
MDAwMDENMAsGA1UEAwwERlIwMDAeFw0xMjExMDExMzQ3NDZaFw0xNTExMDExMzQ3
NDZaMFcxCzAJBgNVBAYTAkZSMRswGQYDVQQKDBJDRVJUSUZJQ0FUIERFIFRFU1Qx
HDAaBgNVBAsMEzAwMDIgMDAwMDAwMDAwMDAwMDAxDTALBgNVBAMMBDAwMDEwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASpjw18zWKAiJO+xNQ2550YNKHW4AHXDxxM
3M2dni/iKfckBRTo3cDKmNDHRAycxJKEmg+9pz/DkvTaCuB/hMI8MA0GCSqGSIb3
DQEBBQUAA4IBAQA6HN+w/bzIdg0ZQF+ELrocplehP7r5JuRJNBAgmoqoER7IonCv
KSNUgUVbJ/MB4UKQ6CgzK7AOlCpiViAnBv+i6fg8Dh9evoUcHBiDvbl19+4iREaO
oyVZ8RAlkp7VJKrC3s6dJEmI8/19obLbTvdHfY+TZfduqpVl63RSxwLG0Fjl0SAQ
z9a+KJSKZnEvT9I0iUUgCSnqFt77RSppziQTZ+rkWcfd+BSorWr8BHqOkLtj7EiV
amIh+g3A8JtwV7nm+NUbBlhh2UPSI0eevsRjQRghtTiEn0wflVBX7xFP9zXpViHq
Ij+R9WiXzWGFYyKuAFK1pQ2QH8BxCbvdNdff
-----END CERTIFICATE-----
"""


def _ref_cert():
    return x509.load_pem_x509_certificate(REF_CERT_PEM)


# --- Example 1 — doc type 12 (header/fields/reconstruction) --------------------

EX1_HEADER = "DC04FR000001198519D31201FR"
EX1_FIELDS = [
    ("90", "MAITRE/SPECIMEN/NATACHA"),
    ("92", "RAISON SOCIALE DE TEST"),
    ("94", "SAISIE CONSERVATOIRE DE CREANCES"),
    ("96", "21112017"),                       # fixed length 8
    ("91", "MME/BERTHIER/CORINNE"),
    ("93", "RAISON SOCIALE DU TIERS CONCERNE"),
    ("95", "1896547853AB"),
    ("0C", "NB2WS43TNFSXELLKOVZXI2LDMUXGM4RPGE4DSNRVGQ3TQNJTIFBA"),
]


def _ex1_encoded() -> str:
    # fixed field 96 carries no separator on the wire
    out = []
    for i, (di, val) in enumerate(EX1_FIELDS):
        out.append(di + val)
        if di != "96" or i == len(EX1_FIELDS) - 1:
            out.append(GS)
    return "".join(out)


def _ex1_payload() -> bytes:
    body = EX1_HEADER + _ex1_encoded() + US + base32.encode(b"\x00" * 64)
    return body.encode("latin-1")


def test_ex1_header():
    h = decode(_ex1_payload()).header
    assert (h.version, h.ca_id, h.cert_id) == (4, "FR00", "0001")
    assert h.document_type == "12" and h.perimeter == "01" and h.country == "FR"
    assert h.emission_date == date(2017, 11, 20)
    assert h.signature_date == date(2018, 2, 6)


def test_ex1_fields():
    doc = decode(_ex1_payload())
    assert doc.field("90").value == "MAITRE/SPECIMEN/NATACHA"
    assert doc.field("96").value == 21112017
    assert doc.field("0C").value == "huissier-justice.fr/1896547853AB"
    assert doc.document_label


def test_ex1_signed_data_reconstruction():
    doc = decode(_ex1_payload())
    # signed form re-inserts the <GS> after fixed field 96
    expected = (EX1_HEADER + "".join(di + v + GS for di, v in EX1_FIELDS)).encode("latin-1")
    assert doc.signed_data != expected            # literal omits the boundary <GS>
    assert expected in doc.signed_data_candidates  # reconstructed candidate matches


# --- Example 2 — doc type B1 (real signature verification) ---------------------

EX2_HEADER = "DC04FR0000011A5E1A5EB101FR"
EX2_ENCODED = (
    "BK18-ROSWFTHR-35"
    "B0CORINNE/NATACHA" + GS +
    "B2BERTHIER" + GS +
    "B3" + GS +
    "B712071973"
    "BB9654321785T" + GS
)
EX2_SIG_HEX = (
    "CDCFA084624484FB5FFAC20B"
    "2601AEF7B4ED225E7BDE8451"
    "86ABB641118BFC69E8209D12"
    "B2AD83B7F48B3D9C2F409742"
    "7A2A5E01C67C1375E46D1D05"
    "E889BED0"
)


def _ex2_payload() -> bytes:
    sig = bytes.fromhex(EX2_SIG_HEX)
    body = EX2_HEADER + EX2_ENCODED + US + base32.encode(sig)
    return body.encode("latin-1")


def test_ex2_decode_and_verify_signature():
    from twoddoc.trust.verify import verify_signature

    doc = decode(_ex2_payload())
    assert doc.header.document_type == "B1"
    assert doc.field("BK").value == "18-ROSWFTHR-35"
    assert doc.field("B7").value == 12071973

    cert = _ref_cert()
    sig = bytes.fromhex(EX2_SIG_HEX)
    assert base32.decode(base32.encode(sig)) == sig
    # at least one signed-data candidate verifies against the real signature
    assert any(
        _try_verify(verify_signature, cert, cand, sig)
        for cand in doc.signed_data_candidates
    )


def _try_verify(fn, cert, data, sig) -> bool:
    try:
        return fn(cert, data, sig)
    except Exception:  # noqa: BLE001
        return False
