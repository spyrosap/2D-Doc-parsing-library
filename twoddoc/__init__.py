"""twoddoc — identify, decode, parse and verify French 2D-Doc codes.

Typical use::

    import twoddoc
    for item in twoddoc.process("bill.pdf"):
        print(item["data"], item["verification"])

Lower-level building blocks::

    codes = twoddoc.detect("bill.pdf")          # locate DataMatrix codes
    doc = twoddoc.decode(codes[0].raw)          # parse header + message
    result = twoddoc.verify(doc)                # signature + chain + revocation
"""

from __future__ import annotations

from typing import Any

from .conformance import Conformance, check_conformance
from .detect import DetectedCode, detect, detect_image, detect_one, detect_pdf
from .errors import (
    CatalogError,
    CertificateRetrievalError,
    DecodeError,
    DetectionError,
    HeaderError,
    MessageError,
    TrustError,
    TSLError,
    TwoDDocError,
    VerificationError,
)
from .model import Encoding, Field, Header, Signature, TwoDDoc, VerificationResult
from .reader import decode

__all__ = [
    "detect", "detect_pdf", "detect_image", "detect_one", "DetectedCode",
    "decode", "parse_pdf", "verify", "process", "check_conformance", "Conformance",
    "TwoDDoc", "Header", "Field", "Signature", "Encoding", "VerificationResult",
    "TwoDDocError", "DetectionError", "DecodeError", "HeaderError", "MessageError",
    "CatalogError", "TrustError", "TSLError", "CertificateRetrievalError",
    "VerificationError",
]

__version__ = "0.1.0"


def parse_pdf(path: str, *, dpi: int = 400) -> list[TwoDDoc]:
    """Detect and decode every 2D-Doc on a PDF."""
    return [decode(c.raw) for c in detect_pdf(path, dpi=dpi)]


def verify(
    doc: TwoDDoc,
    *,
    tsl: Any | None = None,
    resolver: Any | None = None,
    keystore_dir: str | None = None,
    cache_dir: str | None = None,
    check_revocation: bool = True,
) -> VerificationResult:
    """Verify a parsed 2D-Doc against the ANTS TSL.

    Loads/uses a cached TSL, resolves the signing certificate, then verifies the
    signature, certificate chain, validity period and (optionally) revocation.
    """
    from .trust import CertResolver, load_tsl
    from .trust import verify as _verify

    if resolver is None:
        if tsl is None:
            tsl = load_tsl(cache_dir=cache_dir)
        resolver = CertResolver(tsl=tsl, keystore_dir=keystore_dir, cache_dir=cache_dir)
    leaf, anchors = resolver.resolve(doc.header)
    return _verify(doc, leaf, anchors, check_revocation=check_revocation)


def process(
    path: str,
    *,
    dpi: int = 400,
    verify_signatures: bool = True,
    **verify_kwargs: Any,
) -> list[dict[str, Any]]:
    """One-call pipeline: detect → decode → parse → (verify) for a PDF/image.

    Returns one dict per detected code with ``data`` (parsed JSON-able dict),
    ``detected`` (page/bbox) and, when enabled, ``verification``.
    """
    out: list[dict[str, Any]] = []
    for code in detect(path, dpi=dpi):
        doc = decode(code.raw)
        entry: dict[str, Any] = {
            "data": doc.to_dict(),
            "detected": {"page": code.page, "bbox": code.bbox},
            "conformance": check_conformance(doc).to_dict(),
        }
        if verify_signatures:
            try:
                entry["verification"] = verify(doc, **verify_kwargs).to_dict()
            except TwoDDocError as exc:
                entry["verification"] = {"error": str(exc)}
        out.append(entry)
    return out
