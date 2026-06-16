"""Command-line interface: ``twoddoc <file.pdf>`` → JSON."""

from __future__ import annotations

import argparse
import json
import sys

from . import process
from .errors import TwoDDocError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="twoddoc",
        description="Identify, decode, parse and verify 2D-Doc codes on a PDF/image.",
    )
    parser.add_argument("path", help="PDF or image file to scan")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip signature/chain verification")
    parser.add_argument("--no-revocation", action="store_true",
                        help="skip CRL/OCSP revocation checks")
    parser.add_argument("--keystore", metavar="DIR",
                        help="directory of leaf certificates for offline lookup")
    parser.add_argument("--dpi", type=int, default=400,
                        help="rasterisation DPI for PDFs (default: 400)")
    args = parser.parse_args(argv)

    try:
        results = process(
            args.path,
            dpi=args.dpi,
            verify_signatures=not args.no_verify,
            keystore_dir=args.keystore,
            check_revocation=not args.no_revocation,
        )
    except TwoDDocError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not results:
        print("No 2D-Doc found.", file=sys.stderr)
        return 1

    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
