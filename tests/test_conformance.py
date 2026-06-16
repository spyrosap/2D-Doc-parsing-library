"""Structural conformance tests (§8) for document type 00."""

from twoddoc.codecs import base32
from twoddoc.conformance import check_conformance
from twoddoc.message import GS, US
from twoddoc.reader import decode

HEADER = "DC02FR03ENG10E840E8A00"  # v02, AC FR03, doc type 00


def _payload(fields: list[tuple[str, str]]) -> bytes:
    # 24 (5) and 26 (2) are fixed-length; a trailing <GS> after them is ignored.
    msg = "".join(di + val + GS for di, val in fields)
    return (HEADER + msg + US + base32.encode(b"\x00" * 64)).encode("latin-1")


# Full, valid type-00 field set: strict mandatory 20-26 + interchangeable 10.
VALID = [
    ("10", "MR LAMBREY ROMAIN"),
    ("20", " "), ("21", "40 RUE GUSTAVE SIMON"), ("22", " "), ("23", " "),
    ("24", "54000"), ("25", "NANCY"), ("26", "FR"),
]


def test_conformant_document():
    c = check_conformance(decode(_payload(VALID)))
    assert c.conformant is True
    assert c.missing_mandatory == []
    assert c.forbidden_present == []
    assert c.interchangeable_present == ["10"]


def test_missing_mandatory_field():
    fields = [f for f in VALID if f[0] != "26"]  # drop mandatory "Pays"
    c = check_conformance(decode(_payload(fields)))
    assert c.conformant is False
    assert "26" in c.missing_mandatory


def test_interchangeable_group_unsatisfied():
    fields = [f for f in VALID if f[0] != "10"]  # no 10 and no 11/12/13
    c = check_conformance(decode(_payload(fields)))
    assert c.interchangeable_satisfied is False
    assert c.conformant is False


def test_forbidden_field_present():
    # 14 (destinataire address) is forbidden for type 00
    c = check_conformance(decode(_payload(VALID + [("14", "SOMEONE ELSE")])))
    assert "14" in c.forbidden_present
    assert c.conformant is False
