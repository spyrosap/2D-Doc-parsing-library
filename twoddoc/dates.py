"""Date / time conversions used by 2D-Doc.

Two date encodings exist in the standard:

* **C40 headers and most date DIs** — the number of days elapsed since
  2000-01-01, written as a hex string (``FFFF`` = undated). See §3.3.
* **Binary v04 headers / DIs** — the date concatenated as ``MMJJAAAA`` then
  stored as a positive integer on 3 bytes (``FFFFFF`` = undated). See §3.4.2.
"""

from __future__ import annotations

from datetime import date, timedelta

EPOCH = date(2000, 1, 1)

# Sentinels meaning "no date"
_UNDATED_HEX = {"FFFF", "FFFFFF"}


def days_since_2000_to_date(value: str | int) -> date | None:
    """Convert a days-since-2000 value (hex string or int) to a ``date``.

    Returns ``None`` for the undated sentinel.
    """
    if isinstance(value, str):
        if value.upper() in _UNDATED_HEX:
            return None
        n = int(value, 16)
    else:
        n = int(value)
    if n in (0xFFFF, 0xFFFFFF):
        return None
    return EPOCH + timedelta(days=n)


def date_to_days_since_2000(d: date) -> int:
    """Inverse of :func:`days_since_2000_to_date`."""
    return (d - EPOCH).days


def binary_date_to_date(raw: bytes) -> date | None:
    """Decode a 3-byte ``MMJJAAAA`` binary date (§3.4.2 / §3.3.4).

    ``0xFFFFFF`` means undated -> ``None``.
    """
    if len(raw) != 3:
        raise ValueError("binary date must be exactly 3 bytes")
    n = int.from_bytes(raw, "big")
    if n == 0xFFFFFF:
        return None
    s = f"{n:08d}"  # MMJJAAAA
    month, day, year = int(s[0:2]), int(s[2:4]), int(s[4:8])
    return date(year, month, day)


def date_to_binary_date(d: date) -> bytes:
    """Inverse of :func:`binary_date_to_date`."""
    n = int(f"{d.month:02d}{d.day:02d}{d.year:04d}")
    return n.to_bytes(3, "big")


def parse_hhmmss(value: str) -> str:
    """Normalise an ``HHMMSS`` time DI to ``HH:MM:SS`` (DI 07)."""
    if len(value) != 6 or not value.isdigit():
        raise ValueError(f"invalid HHMMSS time: {value!r}")
    return f"{value[0:2]}:{value[2:4]}:{value[4:6]}"
