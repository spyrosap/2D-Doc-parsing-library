"""Codec tests built from the worked examples in §10 of the spec."""

import pytest

from twoddoc.codecs import base32, base256, c40


def test_c40_encode_codewords_2ddoc():
    # §10.3.2: "2D-DOC" -> E6 28 2A 4D C5 FE 44
    assert c40.encode_codewords("2D-DOC") == bytes.fromhex("E6282A4DC5FE44")


def test_c40_decode_codewords_2ddoc():
    assert c40.decode_codewords(bytes.fromhex("E6282A4DC5FE44")) == "2D-DOC"


def test_c40_bare_triplet_fra():
    # §3.3.4: "FRA" -> 0x7BA7 (one full triplet, no prefix)
    assert c40.encode_bytes("FRA") == bytes.fromhex("7BA7")
    assert c40.decode_bytes(bytes.fromhex("7BA7")) == "FRA"


@pytest.mark.parametrize(
    "text",
    [
        "DC04FR0AXT4A0E840E8A0101FR",  # a v04 header
        "AB",                          # exact one-leftover -> unlatch path
        "ABCDEF",                      # multiple of 3
        "ABCDE",                       # two-leftover -> Shift1 pad
        "HELLO 2D-DOC 12345",
        "a",                           # lowercase via Shift3
        "abc/def",
    ],
)
def test_c40_bytes_roundtrip(text):
    assert c40.decode_bytes(c40.encode_bytes(text)) == text


@pytest.mark.parametrize("ctrl", ["\x1d", "\x1e", "\x1f"])  # GS, RS, US
def test_c40_control_chars_roundtrip(ctrl):
    text = f"A{ctrl}B"
    assert c40.decode_bytes(c40.encode_bytes(text)) == text


def test_base32_roundtrip_unpadded():
    data = bytes(range(40))
    encoded = base32.encode(data)  # no '=' padding
    assert "=" not in encoded
    assert base32.decode(encoded) == data


def test_base256_roundtrip():
    data = bytes([0x42, 0x50, 0x47, 0xFB, 0x00, 0x81])
    assert base256.unrandomize(base256.randomize(data)) == data
