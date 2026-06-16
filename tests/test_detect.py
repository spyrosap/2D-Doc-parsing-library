"""Detection end-to-end tests (requirements 1 & 2).

Encodes the reference payload as a real DataMatrix, then exercises detection on
a PIL image and on a generated PDF, decoding back to the original bytes.

Gated on pylibdmtx (needs the system ``libdmtx`` library).
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("PIL")
pylibdmtx = pytest.importorskip("pylibdmtx.pylibdmtx")

from PIL import Image, ImageOps  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from test_reference_v4 import _ex2_payload  # noqa: E402

import twoddoc  # noqa: E402


def _datamatrix_image(payload: bytes, *, scale: int = 8, border: int = 20) -> Image.Image:
    enc = pylibdmtx.encode(payload)
    img = Image.frombytes("RGB", (enc.width, enc.height), enc.pixels).convert("L")
    img = img.resize((img.width * scale, img.height * scale), Image.NEAREST)
    return ImageOps.expand(img, border=border, fill=255)


def test_detect_image_roundtrip():
    payload = _ex2_payload()
    codes = twoddoc.detect_image(_datamatrix_image(payload))
    assert codes, "no DataMatrix detected on the image"
    assert codes[0].raw == payload


def test_detect_image_then_decode():
    payload = _ex2_payload()
    code = twoddoc.detect_image(_datamatrix_image(payload))[0]
    doc = twoddoc.decode(code.raw)
    assert doc.header.ca_id == "FR00"
    assert doc.field("BK").value == "18-ROSWFTHR-35"


def test_detect_pdf(tmp_path):
    pytest.importorskip("pypdfium2")
    payload = _ex2_payload()
    pdf_path = tmp_path / "code.pdf"
    # Pillow can emit a single-page PDF embedding the DataMatrix image.
    _datamatrix_image(payload, scale=10, border=40).convert("RGB").save(
        pdf_path, "PDF", resolution=300
    )
    codes = twoddoc.detect_pdf(pdf_path, dpi=300)
    assert codes, "no DataMatrix detected on the PDF"
    assert codes[0].raw == payload
    assert codes[0].page == 0
