"""Base256 encoding (§10.5).

Used by the **version 1** signature zone. DataMatrix stores Base256 data with a
"255-state randomising algorithm" applied to every codeword (including the
length prefix). When a full DataMatrix reader (pylibdmtx) is used it already
removes this randomisation, so these helpers cover the raw-codeword path and
round-trip testing.
"""

from __future__ import annotations


def _pseudo_random(position: int) -> int:
    return ((149 * position) % 255) + 1


def unrandomize(data: bytes, start_position: int = 1) -> bytes:
    """Reverse the 255-state randomisation (§10.5).

    ``start_position`` is the 1-based codeword position of the first byte of
    ``data`` within the DataMatrix symbol.
    """
    out = bytearray()
    for offset, value in enumerate(data):
        pos = start_position + offset
        temp = value - _pseudo_random(pos)
        out.append(temp if temp >= 0 else temp + 256)
    return bytes(out)


def randomize(data: bytes, start_position: int = 1) -> bytes:
    """Apply the 255-state randomisation (inverse of :func:`unrandomize`)."""
    out = bytearray()
    for offset, value in enumerate(data):
        pos = start_position + offset
        temp = value + _pseudo_random(pos)
        out.append(temp if temp <= 255 else temp - 256)
    return bytes(out)
