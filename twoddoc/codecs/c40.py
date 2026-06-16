"""C40 encoding (§10.3).

C40 packs a restricted character set (upper-case letters, digits, space and,
via *shift* sets, the rest of ASCII) three characters at a time into a 16-bit
value, stored on two bytes.

This module provides:

* :func:`text_to_values` / :func:`values_to_text` — the "phase 1" transform
  between a string and the list of C40 values (0..39), including the shift and
  upper-shift mechanics.
* :func:`encode_bytes` / :func:`decode_bytes` — the "phase 2" packing of C40
  values into the raw 2-byte triplets (used by the **binary** header/message
  fields, which carry bare C40 triplets with no ``230`` prefix).
* :func:`encode_codewords` / :func:`decode_codewords` — the DataMatrix-codeword
  variant prefixed with ``0xE6`` (230), matching the worked example in §10.3.2.

The runtime decode path normally relies on the DataMatrix reader (pylibdmtx)
to return the already-decoded payload; these functions cover the binary format
and round-trip testing.
"""

from __future__ import annotations

from ..errors import DecodeError

LATCH_C40 = 0xE6      # 230 — switch ASCII -> C40
UNLATCH = 0xFE        # 254 — switch C40 -> ASCII

# --- character <-> C40 value tables (Tableau 3) --------------------------------

# Base set: 0,1,2 are Shift1/2/3; 3 = space; 4-13 = '0'-'9'; 14-39 = 'A'-'Z'.
_BASE_VAL_TO_CHR: dict[int, str] = {3: " "}
for _i in range(10):
    _BASE_VAL_TO_CHR[4 + _i] = chr(ord("0") + _i)
for _i in range(26):
    _BASE_VAL_TO_CHR[14 + _i] = chr(ord("A") + _i)

# Shift1: value v -> ASCII v (0..31)
_SHIFT1_VAL_TO_CHR: dict[int, str] = {v: chr(v) for v in range(32)}

# Shift2: punctuation. Values 0..26 map to the chars below; 30 = Upper Shift.
_SHIFT2_CHARS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_"  # 27 chars, values 0..26
_SHIFT2_VAL_TO_CHR: dict[int, str] = {v: c for v, c in enumerate(_SHIFT2_CHARS)}
_UPPER_SHIFT = 30

# Shift3: value v -> ASCII 96+v (96..127)
_SHIFT3_VAL_TO_CHR: dict[int, str] = {v: chr(96 + v) for v in range(32)}

# Reverse maps for encoding
_CHR_TO_BASE = {c: v for v, c in _BASE_VAL_TO_CHR.items()}
_CHR_TO_SHIFT2 = {c: v for v, c in _SHIFT2_VAL_TO_CHR.items()}


# --- phase 1: text <-> C40 values ---------------------------------------------

def _char_to_values(ch: str) -> list[int]:
    code = ord(ch)
    if code > 0xFF:
        raise DecodeError(f"character {ch!r} is outside ISO-8859-1, cannot C40-encode")
    if code >= 128:  # extended ASCII -> upper shift then encode (code-128)
        return [1, _UPPER_SHIFT] + _char_to_values(chr(code - 128))
    if ch in _CHR_TO_BASE:
        return [_CHR_TO_BASE[ch]]
    if code <= 31:  # Shift1
        return [0, code]
    if ch in _CHR_TO_SHIFT2:  # Shift2 punctuation
        return [1, _CHR_TO_SHIFT2[ch]]
    if 96 <= code <= 127:  # Shift3
        return [2, code - 96]
    raise DecodeError(f"character {ch!r} cannot be encoded in C40")


def text_to_values(text: str) -> list[int]:
    """Transform a string into the list of C40 values (phase 1)."""
    values: list[int] = []
    for ch in text:
        values.extend(_char_to_values(ch))
    return values


def values_to_text(values: list[int]) -> str:
    """Inverse of :func:`text_to_values` (phase 1)."""
    out: list[str] = []
    i = 0
    n = len(values)
    upper = False

    def emit(c: str) -> None:
        nonlocal upper
        if upper:
            out.append(chr((ord(c) + 128) & 0xFF))
            upper = False
        else:
            out.append(c)

    while i < n:
        v = values[i]
        if v == 0:      # Shift1
            i += 1
            if i >= n:
                break
            emit(_SHIFT1_VAL_TO_CHR[values[i]])
        elif v == 1:    # Shift2
            i += 1
            if i >= n:
                break
            w = values[i]
            if w == _UPPER_SHIFT:
                upper = True
            elif w in _SHIFT2_VAL_TO_CHR:
                emit(_SHIFT2_VAL_TO_CHR[w])
            else:
                raise DecodeError(f"unsupported Shift2 value {w}")
        elif v == 2:    # Shift3
            i += 1
            if i >= n:
                break
            emit(_SHIFT3_VAL_TO_CHR[values[i]])
        else:
            if v not in _BASE_VAL_TO_CHR:
                raise DecodeError(f"invalid base C40 value {v}")
            emit(_BASE_VAL_TO_CHR[v])
        i += 1
    return "".join(out)


# --- phase 2: C40 values <-> packed bytes --------------------------------------

def _pack_triplet(c1: int, c2: int, c3: int) -> bytes:
    enc = 1600 * c1 + 40 * c2 + c3 + 1
    return bytes((enc >> 8, enc & 0xFF))


def encode_bytes(text: str) -> bytes:
    """Pack ``text`` into bare C40 triplet bytes (no ``230`` prefix).

    Used for binary-format fields. The trailing-character rules of §10.3.2 are
    applied: a final lone value triggers an ``0xFE`` unlatch + ASCII byte; a
    final pair is padded with ``<Shift1>`` (value 0).
    """
    values = text_to_values(text)
    out = bytearray()
    i = 0
    while i + 3 <= len(values):
        out += _pack_triplet(values[i], values[i + 1], values[i + 2])
        i += 3
    rest = values[i:]
    if len(rest) == 2:
        out += _pack_triplet(rest[0], rest[1], 0)  # pad with Shift1
    elif len(rest) == 1:
        # cannot represent a single value as a triplet -> unlatch and ASCII-encode
        # the original last character.
        out.append(UNLATCH)
        out.append((ord(text[-1]) + 1) & 0xFF)
    return bytes(out)


def decode_bytes(data: bytes) -> str:
    """Decode bare C40 triplet bytes (inverse of :func:`encode_bytes`)."""
    values: list[int] = []
    i = 0
    tail = ""
    n = len(data)
    while i < n:
        b = data[i]
        if b == UNLATCH:
            # remainder is ASCII codewords (char = byte - 1)
            for c in data[i + 1:]:
                tail += chr((c - 1) & 0xFF)
            break
        if i + 1 >= n:
            raise DecodeError("dangling C40 byte without its pair")
        enc = (b << 8) | data[i + 1]
        val = enc - 1
        c1, val = divmod(val, 1600)
        c2, c3 = divmod(val, 40)
        values.extend((c1, c2, c3))
        i += 2
    # A pair padded with Shift1 leaves a trailing value 0 we must drop.
    if values and values[-1] == 0:
        values = values[:-1]
    return values_to_text(values) + tail


# --- DataMatrix-codeword variant (with 230 prefix) -----------------------------

def encode_codewords(text: str) -> bytes:
    """Encode ``text`` as a DataMatrix C40 segment, prefixed with ``230``.

    Matches §10.3.2 ("2D-DOC" -> ``E6 28 2A 4D C5 FE 44``).
    """
    return bytes((LATCH_C40,)) + encode_bytes(text)


def decode_codewords(data: bytes) -> str:
    """Decode a DataMatrix C40 segment that starts with ``230``."""
    if not data or data[0] != LATCH_C40:
        raise DecodeError("C40 codeword stream must start with 0xE6 (230)")
    return decode_bytes(data[1:])
