#!/usr/bin/env python3
"""Generate a curated grep-target map: only the fields that make sense to check.

Output: twoddoc/catalog/data/grep_targets_curated.json

Same shape as grep_targets.json but pruned per document type. Selection rule:

    keep a field iff signal == "strong" AND obligation in {O, O*}

i.e. only discriminating, **mandatory** fields (guaranteed present for the type).
Drops WEAK fields (year, country code, small counts) and all FACULTATIVE fields.

Usage:
    python tools/build_grep_targets_curated.py
"""

from __future__ import annotations

import json
from pathlib import Path

from twoddoc.catalog import get_catalog

OUT = Path("twoddoc/catalog/data/grep_targets_curated.json")


def est_signal(di) -> str:
    if di is None:
        return "strong"
    if di.kind == "date_days2000":
        return "strong"
    if di.kind == "time":
        return "weak"
    size = di.max if di.max is not None else 999
    return "strong" if size >= 5 else "weak"


def main() -> None:
    cat = get_catalog()
    reqs = cat._requirements
    doctypes = cat._doc_types["01"]

    out: dict[str, dict] = {}
    for code in sorted(reqs):
        r = reqs[code]
        obligation = {}
        for fid in r.get("mandatory", []):
            obligation[fid] = "O"
        for fid in r.get("mandatory_alt", []):
            obligation[fid] = "O*"

        kept, fields = [], {}
        for fid in sorted(f for f in obligation if not f.startswith("0")):  # §3.4
            di = cat.data_id(fid)
            if est_signal(di) != "strong":
                continue
            kept.append(fid)
            fields[fid] = {"label": di.label if di else None,
                           "kind": di.kind if di else None,
                           "obligation": obligation[fid]}

        interchangeable = sorted(f for f in r.get("mandatory_alt", []) if f in kept)
        types = doctypes.get(code, {}).get("types") or []
        out[code] = {
            "label": types[0] if types else None,
            "grep": kept,
            "interchangeable_groups": [interchangeable] if interchangeable else [],
            "fields": fields,
        }

    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} ({len(out)} document types)")


if __name__ == "__main__":
    main()
