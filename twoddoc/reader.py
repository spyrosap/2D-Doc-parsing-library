"""Top-level decode: turn a raw 2D-Doc payload into a :class:`TwoDDoc`.

The raw payload is what a DataMatrix reader returns (e.g. pylibdmtx): the fully
decoded byte stream of the code. This module detects the format (C40 text vs
binary), parses the header, splits the data zone from the signature, and parses
the message against the catalog.
"""

from __future__ import annotations

from .catalog import get_catalog
from .codecs import base32
from .errors import DecodeError
from .header import c40_header_length, parse_binary_header, parse_c40_header
from .message import (
    US,
    parse_binary_message,
    parse_c40_message,
    signed_data_candidates,
)
from .model import Signature, TwoDDoc

_BASE32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _annotate_obligation(fields, doc_type: str) -> None:
    """Tag each field as mandatory/optional per the doc type's §8 requirements."""
    mandatory = set(get_catalog().mandatory_ids(doc_type))
    for f in fields:
        f.mandatory = f.id in mandatory


def decode(raw: bytes) -> TwoDDoc:
    """Decode a raw 2D-Doc payload into a parsed :class:`TwoDDoc`."""
    if not raw:
        raise DecodeError("empty payload")
    if raw[0] == 0xDC:
        return _decode_binary(raw)
    if raw[:2] == b"DC":
        return _decode_c40(raw)
    raise DecodeError(f"unrecognised 2D-Doc marker: {raw[:2]!r}")


def _split_signature_annexe(region: str) -> tuple[str, str]:
    """Split a post-<US> region into (base32 signature, annexe remainder).

    The signature is a Base32 run; the optional v04 annexe (unsigned) starts at
    the first character outside the Base32 alphabet.
    """
    end = len(region)
    for idx, ch in enumerate(region):
        if ch not in _BASE32_ALPHABET:
            end = idx
            break
    return region[:end], region[end:]


def _decode_c40(raw: bytes) -> TwoDDoc:
    text = raw.decode("latin-1")
    header = parse_c40_header(text)
    perimeter = header.perimeter or "01"
    hlen = c40_header_length(header.version)
    body = text[hlen:]

    annexe_fields = []
    candidates: list[bytes] = []
    if header.version >= 2:
        us = body.find(US)
        if us == -1:
            message_str, sig_b32, annexe_str = body, "", ""
            signed_data = text.encode("latin-1")
        else:
            message_str = body[:us]
            sig_b32, annexe_str = _split_signature_annexe(body[us + 1:])
            signed_data = text[: hlen + us].encode("latin-1")
        signature = Signature(
            raw=base32.decode(sig_b32) if sig_b32 else b"", encoding="base32"
        )
        candidates = signed_data_candidates(
            header.raw, message_str, perimeter, header.document_type
        )
        if annexe_str:
            annexe_fields = parse_c40_message(annexe_str, perimeter)
    else:
        # v01: Base256 signature appended with no <US> delimiter. Splitting the
        # signature from the message requires the raw codeword stream; here we
        # parse the data zone best-effort and leave the signature empty.
        message_str = body
        signed_data = text.encode("latin-1")
        signature = Signature(raw=b"", encoding="base256")

    fields = parse_c40_message(message_str, perimeter)
    _annotate_obligation(fields, header.document_type)
    cat = get_catalog()
    return TwoDDoc(
        header=header,
        fields=fields,
        signature=signature,
        signed_data=signed_data,
        signed_data_candidates=candidates or [signed_data],
        annexe=annexe_fields,
        document_label=cat.document_label(header.document_type, perimeter),
        perimeter_label=cat.perimeter_label(perimeter),
    )


def _decode_binary(raw: bytes) -> TwoDDoc:
    header = parse_binary_header(raw[:19])
    perimeter = header.perimeter or "0001"
    fields, sig_offset = parse_binary_message(raw[19:], perimeter)
    _annotate_obligation(fields, header.document_type)
    abs_sig = 19 + sig_offset
    signed_data = raw[:abs_sig]
    # skip the 0xFF marker (if present) to get the signature bytes
    sig_start = abs_sig + 1 if abs_sig < len(raw) else abs_sig
    signature = Signature(raw=raw[sig_start:], encoding="binary")

    cat = get_catalog()
    return TwoDDoc(
        header=header,
        fields=fields,
        signature=signature,
        signed_data=signed_data,
        document_label=cat.document_label(header.document_type, perimeter)
        or cat.document_label(header.document_type, "01"),
        perimeter_label=cat.perimeter_label(perimeter),
    )
