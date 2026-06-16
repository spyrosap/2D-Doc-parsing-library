"""DataMatrix ASCII codeword codec (§10.2 / §10.6).

A DataMatrix payload is a stream of *codewords*. The default scheme is ASCII,
which can latch into C40 (``230``) or Base256 (``231``). This module decodes the
subset of the ASCII scheme used by 2D-Doc, so the library can parse a raw
codeword stream itself (binary format, or when a reader exposes raw codewords).

For the common case the higher-level reader uses pylibdmtx, which already
returns the fully decoded payload; this module is the explicit fallback.
"""

from __future__ import annotations

from ..errors import DecodeError
from . import base256, c40

PAD = 0x81          # 129 — start of padding
LATCH_C40 = 0xE6    # 230
LATCH_BASE256 = 0xE7  # 231
UPPER_SHIFT = 0xEB  # 235
UNLATCH = 0xFE      # 254


def decode_codewords(data: bytes) -> bytes:
    """Decode a DataMatrix codeword stream to its payload bytes.

    Handles ASCII chars, double-digit packing, the C40 and Base256 latches,
    the extended-ASCII upper-shift and the ``129`` padding terminator.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == PAD:
            break  # padding zone -> end of message
        if 1 <= b <= 128:
            out.append(b - 1)
            i += 1
        elif 130 <= b <= 229:  # two digits 00..99
            out.extend(f"{b - 130:02d}".encode("ascii"))
            i += 1
        elif b == UPPER_SHIFT:
            if i + 1 >= n:
                raise DecodeError("dangling upper-shift codeword")
            out.append((data[i + 1] - 1 + 128) & 0xFF)
            i += 2
        elif b == LATCH_C40:
            j = i + 1
            while j < n and data[j] != UNLATCH:
                j += 1
            out.extend(c40.decode_bytes(data[i + 1:j]).encode("latin-1"))
            i = j + 1 if j < n else j
        elif b == LATCH_BASE256:
            i += 1
            # length byte(s), randomised; position is 1-based codeword index
            d1 = base256.unrandomize(data[i:i + 1], i + 1)[0]
            i += 1
            if d1 == 0:
                length = n - i  # rest of symbol
            elif d1 <= 249:
                length = d1
            else:
                d2 = base256.unrandomize(data[i:i + 1], i + 1)[0]
                i += 1
                length = (d1 - 249) * 250 + d2
            out.extend(base256.unrandomize(data[i:i + length], i + 1))
            i += length
        elif b == UNLATCH:
            i += 1  # already in ASCII
        else:
            raise DecodeError(f"unsupported ASCII codeword {b} at position {i}")
    return bytes(out)
