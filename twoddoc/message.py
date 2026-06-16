"""Message-zone parsing (§3.4).

Two encodings:

* **C40 text** — ``[2-char DI][value]`` blocks. Variable fields end with
  ``<GS>`` (0x1D); a *truncated* field ends with ``<RS>`` (0x1E); fixed-length
  fields carry no separator; the last field needs none unless truncated.
* **Binary** — ``[1-byte DI][1or3-byte length][value]`` blocks. An ID byte of
  ``0xFF`` is reserved to mark the start of the signature (§3.4.2).
"""

from __future__ import annotations

from .catalog import DataId, get_catalog
from .codecs import base32, c40
from .dates import binary_date_to_date, days_since_2000_to_date, parse_hhmmss
from .errors import MessageError
from .model import Field

GS = "\x1d"   # group separator — end of a variable field
RS = "\x1e"   # record separator — end of a truncated field
US = "\x1f"   # unit separator — start of signature (handled by reader)
SEPARATORS = (GS, RS)


# --- value conversion ----------------------------------------------------------

def _convert(di: DataId | None, raw: str) -> object:
    if di is None:
        return raw
    kind = di.kind
    try:
        if kind == "date_days2000":
            return days_since_2000_to_date(raw)
        if kind == "time":
            return parse_hhmmss(raw)
        if kind == "numeric":
            return int(raw) if raw.isdigit() else raw
        if kind == "base32":
            data = base32.decode(raw)
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data
    except (ValueError, Exception):  # noqa: BLE001 - keep raw on any conversion issue
        return raw
    return raw


# --- C40 message ---------------------------------------------------------------

def parse_c40_message(message: str, perimeter: str = "01") -> list[Field]:
    """Parse a decoded C40 message string into a list of :class:`Field`."""
    cat = get_catalog()
    fields: list[Field] = []
    i = 0
    n = len(message)
    while i < n:
        if message[i] in SEPARATORS:
            i += 1
            continue
        if i + 2 > n:
            raise MessageError(f"dangling data identifier at offset {i}")
        di_id = message[i:i + 2]
        i += 2
        di = cat.data_id(di_id, perimeter)

        truncated = False
        if di is not None and di.fixed_length:
            size = di.fixed_size or 0
            value = message[i:i + size]
            i += size
            # a fixed field may still be followed by a stray separator; skip it
        else:
            # variable-length: read until GS/RS or end of string
            start = i
            while i < n and message[i] not in SEPARATORS:
                i += 1
            value = message[start:i]
            if i < n:
                truncated = message[i] == RS
                i += 1  # consume the separator

        label = di.label if di else f"Unknown DI {di_id}"
        fields.append(
            Field(id=di_id, label=label, raw_value=value,
                  value=_convert(di, value), truncated=truncated)
        )
    return fields


def signed_data_candidates(header_raw: str, message: str, perimeter: str,
                           doc_type: str) -> list[bytes]:
    """Return candidate byte strings the signature may cover (§3.5).

    The encoded data zone and the bytes actually signed can differ by a ``<GS>``
    dropped at the mandatory→facultatif boundary when the last mandatory field is
    fixed-length (confirmed by the §16 reference codes). We return the literal
    data zone plus, when applicable, a variant with that separator re-inserted.
    """
    cat = get_catalog()
    mandatory = set(cat.mandatory_ids(doc_type))

    # Re-walk the message recording, per field, the offset just after its value
    # and whether a separator was consumed.
    spans: list[tuple[str, int, int]] = []  # (di, value_end_offset, sep_len)
    i, n = 0, len(message)
    while i < n:
        if message[i] in SEPARATORS:
            i += 1
            continue
        if i + 2 > n:
            break
        di_id = message[i:i + 2]
        i += 2
        di = cat.data_id(di_id, perimeter)
        if di is not None and di.fixed_length:
            i += di.fixed_size or 0
            value_end, sep_len = i, 0
        else:
            while i < n and message[i] not in SEPARATORS:
                i += 1
            value_end = i
            sep_len = 1 if i < n else 0
            i += sep_len
        spans.append((di_id, value_end, sep_len))

    literal = (header_raw + message).encode("latin-1")
    candidates = [literal]

    # Insert a <GS> after a fixed mandatory field directly followed by a
    # facultatif field with no existing separator.
    inserts: list[int] = []
    for k in range(len(spans) - 1):
        di_id, value_end, sep_len = spans[k]
        next_di = spans[k + 1][0]
        if sep_len == 0 and di_id in mandatory and next_di not in mandatory:
            inserts.append(value_end)
    if inserts:
        msg = message
        for off in sorted(inserts, reverse=True):
            msg = msg[:off] + GS + msg[off:]
        candidates.append((header_raw + msg).encode("latin-1"))
    return candidates


# --- Binary message ------------------------------------------------------------

SIGNATURE_MARKER = 0xFF


def parse_binary_message(data: bytes, perimeter: str = "0001") -> tuple[list[Field], int]:
    """Parse a binary message; return (fields, signature_offset).

    ``signature_offset`` is the index of the ``0xFF`` marker (start of the
    signature) or ``len(data)`` if absent.
    """
    cat = get_catalog()
    fields: list[Field] = []
    i = 0
    n = len(data)
    while i < n:
        di_byte = data[i]
        if di_byte == SIGNATURE_MARKER:
            return fields, i
        i += 1
        if i >= n:
            raise MessageError("binary block missing length byte")
        length = data[i]
        i += 1
        if length == 0xFF:
            if i + 2 > n:
                raise MessageError("binary block missing extended length")
            length = (data[i] << 8) | data[i + 1]
            i += 2
        value = data[i:i + length]
        i += length

        di_id = f"{di_byte:02X}"
        di = cat.data_id(di_id, perimeter) or cat.data_id(di_id, "01")
        fields.append(
            Field(id=di_id, label=di.label if di else f"Unknown DI {di_id}",
                  raw_value=value, value=_convert_binary(di, value))
        )
    return fields, n


def _convert_binary(di: DataId | None, raw: bytes) -> object:
    """Best-effort conversion of a binary field value."""
    if di is not None:
        if di.kind == "date_days2000" and len(raw) == 3:
            return binary_date_to_date(raw)
        if di.kind == "numeric":
            return int.from_bytes(raw, "big")
    # alphanumeric strings are C40-encoded in the binary format
    try:
        return c40.decode_bytes(raw)
    except Exception:  # noqa: BLE001
        return raw
