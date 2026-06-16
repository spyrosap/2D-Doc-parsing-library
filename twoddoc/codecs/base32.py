"""Base32 encoding (§10.4) — RFC 4648.

The 2D-Doc signature (v02+) and a few text DIs (e.g. URLs) are Base32 encoded.
Per §10.4 the ``=`` padding characters are *not* stored in the code, so on
decode we re-pad to a multiple of 8 characters.
"""

from __future__ import annotations

import base64

from ..errors import DecodeError


def decode(data: str | bytes) -> bytes:
    """Decode a (possibly unpadded) RFC 4648 Base32 string to bytes."""
    if isinstance(data, bytes):
        data = data.decode("ascii")
    s = data.strip().upper()
    pad = (-len(s)) % 8
    s = s + ("=" * pad)
    try:
        return base64.b32decode(s)
    except Exception as exc:  # pragma: no cover - defensive
        raise DecodeError(f"invalid Base32 data: {exc}") from exc


def encode(data: bytes, *, strip_padding: bool = True) -> str:
    """Encode bytes to Base32; drops ``=`` padding by default (per §10.4)."""
    s = base64.b32encode(data).decode("ascii")
    return s.rstrip("=") if strip_padding else s
