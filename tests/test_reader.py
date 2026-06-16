"""Header + message + reader tests using hand-built payloads."""

from datetime import date

from twoddoc.codecs import base32, c40
from twoddoc.message import GS, RS, US
from twoddoc.model import Encoding
from twoddoc.reader import decode


def _c40_payload(header: str, message: str, sig: bytes, annexe: str = "") -> bytes:
    body = header + message + US + base32.encode(sig) + annexe
    return body.encode("latin-1")


def test_header_v03_fields():
    # §3.3.2 example header (v03), perimeter 01, doc type 01
    payload = _c40_payload("DC03FR0AXT4A0E840E8A0101", "26FR10DOE", b"\x00" * 64)
    doc = decode(payload)
    h = doc.header
    assert h.version == 3
    assert h.encoding is Encoding.C40
    assert h.ca_id == "FR0A"
    assert h.cert_id == "XT4A"
    assert h.emission_date == date(2010, 3, 5)
    assert h.signature_date == date(2010, 3, 11)
    assert h.document_type == "01"
    assert h.perimeter == "01"


def test_message_fixed_and_variable_fields():
    payload = _c40_payload("DC03FR0AXT4A0E840E8A0101", "26FR10DOE", b"\x00" * 64)
    doc = decode(payload)
    assert doc.field("26").value == "FR"        # fixed length 2
    assert doc.field("10").raw_value == "DOE"   # variable, last field


def test_signed_data_excludes_us_and_signature():
    header, message = "DC03FR0AXT4A0E840E8A0101", "26FR10DOE"
    payload = _c40_payload(header, message, b"\x01" * 64)
    doc = decode(payload)
    assert doc.signed_data == (header + message).encode("latin-1")
    assert doc.signature.raw == b"\x01" * 64
    assert doc.signature.encoding == "base32"


def test_truncated_field_marked():
    # variable field 22 truncated (ends with RS); 26 fixed afterwards
    message = "22MARSE" + RS + "26FR"
    payload = _c40_payload("DC03FR0AXT4A0E840E8A0101", message, b"\x00" * 64)
    doc = decode(payload)
    f22 = doc.field("22")
    assert f22.truncated is True
    assert f22.raw_value == "MARSE"
    assert doc.field("26").value == "FR"


def test_gs_separated_variable_fields():
    message = "10JOHN DOE" + GS + "18INV12345"
    payload = _c40_payload("DC03FR0AXT4A0E840E8A0101", message, b"\x00" * 64)
    doc = decode(payload)
    assert doc.field("10").raw_value == "JOHN DOE"
    assert doc.field("18").raw_value == "INV12345"


def test_v04_header_country_and_annexe_split():
    # v04 header (26 chars) + message + signature + annexe (starts with digit DI)
    header = "DC04FR0AXT4A0E840E8A0101FR"
    payload = _c40_payload(header, "26FR", b"\xAA" * 64, annexe="01ANNEXVALUE")
    doc = decode(payload)
    assert doc.header.version == 4
    assert doc.header.country == "FR"
    assert doc.signature.raw == b"\xAA" * 64
    # annexe parsed separately and not part of signed data
    assert doc.signed_data == (header + "26FR").encode("latin-1")
    assert any(f.id == "01" for f in doc.annexe)
