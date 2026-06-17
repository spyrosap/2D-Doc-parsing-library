#!/usr/bin/env python3
"""Generate a simple per-document-type map of *common* field ids.

Output: twoddoc/catalog/data/common_fields_by_document_type.json

"Common" = a printable (id>=10) field whose DI id is used by more than one
document type. DI ids are defined once per perimeter, so a shared id means the
same thing in every type. Result shape: { document_type: [field_id, ...] }.

Usage:
    python tools/build_common_fields.py
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

from twoddoc.catalog import get_catalog

OUT = Path("twoddoc/catalog/data/common_fields_by_document_type.json")


def main() -> None:
    reqs = get_catalog()._requirements

    def printable_ids(code: str) -> set[str]:
        r = reqs[code]
        ids = r.get("mandatory", []) + r.get("mandatory_alt", []) + r.get("facultative", [])
        return {f for f in ids if not f.startswith("0")}

    # count how many document types use each printable id
    usage = collections.Counter()
    for code in reqs:
        for fid in printable_ids(code):
            usage[fid] += 1

    out = {
        code: sorted(f for f in printable_ids(code) if usage[f] > 1)
        for code in sorted(reqs)
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} ({len(out)} document types)")


if __name__ == "__main__":
    main()
