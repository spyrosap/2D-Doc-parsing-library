"""Locate and read 2D-Doc DataMatrix codes on a PDF or image (§4, §5).

PDF pages are rasterised with pypdfium2 and scanned with pylibdmtx. Any decoded
symbol whose payload looks like a 2D-Doc (``DC`` marker or ``0xDC`` binary
marker) is returned with its page index and bounding box.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import DetectionError

if TYPE_CHECKING:  # pragma: no cover
    from PIL.Image import Image

# 400 dpi resolves dense codes (e.g. DGFiP avis d'impôt) that 300 dpi cannot;
# combined with max_count=1 a present code is located in well under a second.
DEFAULT_DPI = 400
# libdmtx does an exhaustive scan; bound it so the no-code case stays fast.
DEFAULT_TIMEOUT_MS = 20000
# Stop at the first DataMatrix: a 2D-Doc document carries a single code, and
# searching on for more is what made full-page scans take minutes.
DEFAULT_MAX_COUNT = 1


@dataclass
class DetectedCode:
    """A DataMatrix located on a document."""

    raw: bytes
    page: int | None = None
    bbox: tuple[int, int, int, int] | None = None  # (left, top, width, height) px


def _looks_like_2ddoc(data: bytes) -> bool:
    return data[:2] == b"DC" or (len(data) > 1 and data[0] == 0xDC)


def _decode_image(
    image: "Image",
    page: int | None = None,
    *,
    timeout_ms: int | None = DEFAULT_TIMEOUT_MS,
    max_count: int | None = DEFAULT_MAX_COUNT,
) -> list[DetectedCode]:
    from pylibdmtx import pylibdmtx  # imported lazily (needs system libdmtx)

    kwargs: dict = {}
    if timeout_ms is not None:
        kwargs["timeout"] = timeout_ms
    if max_count is not None:
        kwargs["max_count"] = max_count

    results: list[DetectedCode] = []
    for res in pylibdmtx.decode(image, **kwargs):
        data = bytes(res.data)
        if _looks_like_2ddoc(data):
            r = res.rect
            results.append(
                DetectedCode(raw=data, page=page, bbox=(r.left, r.top, r.width, r.height))
            )
    return results


def detect_image(
    image: "Image", *, timeout_ms: int | None = DEFAULT_TIMEOUT_MS,
    max_count: int | None = DEFAULT_MAX_COUNT,
) -> list[DetectedCode]:
    """Detect 2D-Doc codes on a single PIL image."""
    return _decode_image(image, timeout_ms=timeout_ms, max_count=max_count)


def detect_pdf(
    path: str | Path, *, dpi: int = DEFAULT_DPI,
    timeout_ms: int | None = DEFAULT_TIMEOUT_MS,
    max_count: int | None = DEFAULT_MAX_COUNT,
    stop_on_first_page: bool = True,
) -> list[DetectedCode]:
    """Detect 2D-Doc codes across the pages of a PDF.

    By default returns as soon as a page yields a code (2D-Docs are virtually
    always single); set ``stop_on_first_page=False`` to scan every page.
    """
    import pypdfium2 as pdfium

    path = Path(path)
    scale = dpi / 72.0
    found: list[DetectedCode] = []
    pdf = pdfium.PdfDocument(str(path))
    try:
        for page_index in range(len(pdf)):
            page = pdf[page_index]
            image = page.render(scale=scale, grayscale=True).to_pil()
            hits = _decode_image(
                image, page=page_index, timeout_ms=timeout_ms, max_count=max_count
            )
            found.extend(hits)
            if hits and stop_on_first_page:
                break
    finally:
        pdf.close()
    return found


def detect(
    source: str | Path | "Image", *, dpi: int = DEFAULT_DPI,
    timeout_ms: int | None = DEFAULT_TIMEOUT_MS,
    max_count: int | None = DEFAULT_MAX_COUNT,
) -> list[DetectedCode]:
    """Detect 2D-Doc codes on a PDF path or a PIL image."""
    if isinstance(source, (str, Path)):
        p = Path(source)
        if p.suffix.lower() == ".pdf":
            return detect_pdf(p, dpi=dpi, timeout_ms=timeout_ms, max_count=max_count)
        from PIL import Image as PILImage

        with PILImage.open(p) as img:
            return detect_image(img.convert("L"), timeout_ms=timeout_ms, max_count=max_count)
    return detect_image(source, timeout_ms=timeout_ms, max_count=max_count)


def detect_one(source: str | Path | "Image", **kwargs) -> DetectedCode:
    """Detect and return exactly one 2D-Doc, raising if none found."""
    codes = detect(source, **kwargs)
    if not codes:
        raise DetectionError("no 2D-Doc DataMatrix found")
    return codes[0]
