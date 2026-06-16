"""2D-Doc header parsing (§3.3).

Two header encodings exist:

* **C40 text** — after the DataMatrix reader decodes the C40 segment, the header
  is plain text of fixed length per version (22 / 24 / 26 chars).
* **Binary** (v04) — a fixed 19-byte structure (§3.3.4).
"""

from __future__ import annotations

from .codecs import c40
from .dates import binary_date_to_date, days_since_2000_to_date
from .errors import HeaderError
from .model import Encoding, Header

MARKER_C40 = "DC"
MARKER_BINARY = 0xDC

# C40 header length per version (chars)
_C40_LEN = {1: 22, 2: 22, 3: 24, 4: 26}


def parse_c40_header(text: str) -> Header:
    """Parse a C40 (text) header from the start of a decoded data zone."""
    if not text.startswith(MARKER_C40):
        raise HeaderError(f"missing 'DC' marker, got {text[:2]!r}")
    try:
        version = int(text[2:4])
    except ValueError as exc:
        raise HeaderError(f"invalid version field {text[2:4]!r}") from exc
    if version not in _C40_LEN:
        raise HeaderError(f"unsupported version {version}")

    length = _C40_LEN[version]
    if len(text) < length:
        raise HeaderError(f"header too short for v{version}: need {length}, got {len(text)}")

    ca_id = text[4:8]
    cert_id = text[8:12]
    emission = days_since_2000_to_date(text[12:16])
    signature = days_since_2000_to_date(text[16:20])
    document_type = text[20:22]
    perimeter = None
    country = None
    if version >= 3:
        perimeter = text[22:24]
    else:
        perimeter = "01"  # v01/v02 are implicitly perimeter '01'
    if version >= 4:
        country = text[24:26]

    return Header(
        marker=MARKER_C40,
        version=version,
        encoding=Encoding.C40,
        ca_id=ca_id,
        cert_id=cert_id,
        emission_date=emission,
        signature_date=signature,
        document_type=document_type,
        perimeter=perimeter,
        country=country,
        raw=text[:length],
    )


def parse_binary_header(data: bytes) -> Header:
    """Parse a 19-byte binary v04 header (§3.3.4)."""
    if len(data) < 19:
        raise HeaderError(f"binary header too short: {len(data)} < 19")
    if data[0] != MARKER_BINARY:
        raise HeaderError(f"missing 0xDC marker, got {data[0]:#04x}")
    version = data[1]
    if version != 4:
        raise HeaderError(f"binary header only defined for v04, got {version}")

    country = c40.decode_bytes(data[2:4])              # ISO-3166 alpha3
    identifier = c40.decode_bytes(data[4:10])          # 9 chars: 4 AC + 5 cert
    ca_id = identifier[:4]
    cert_id = identifier[4:]
    emission = binary_date_to_date(data[10:13])
    signature = binary_date_to_date(data[13:16])
    document_type = f"{data[16]:02X}"
    perimeter = data[17:19].hex().upper()

    return Header(
        marker="DC",
        version=version,
        encoding=Encoding.BINARY,
        ca_id=ca_id,
        cert_id=cert_id,
        emission_date=emission,
        signature_date=signature,
        document_type=document_type,
        perimeter=perimeter,
        country=country,
        raw=data[:19].hex().upper(),
    )


def c40_header_length(version: int) -> int:
    """Length in chars of a C40 header for ``version``."""
    try:
        return _C40_LEN[version]
    except KeyError as exc:
        raise HeaderError(f"unsupported version {version}") from exc
