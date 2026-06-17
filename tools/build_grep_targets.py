#!/usr/bin/env python3
"""Generate a per-document-type grep-target map from the catalog + the rules.

Output: twoddoc/catalog/data/grep_targets.json

For each document type, lists the message fields that are eligible to grep
(printed in clear per §3.4 -> id does not start with '0'), split into a STRONG
set (estimated discriminating, drives a consistency verdict) and a WEAK set
(informational only), plus the O* interchangeable group(s) and per-field
metadata (label, kind, obligation).

Importance here is a STATIC estimate from each field's declared size/kind; at
runtime, classify() on the actual value is authoritative (see
docs/consistency-check-spec.md §4).

Usage:
    python tools/build_grep_targets.py
"""

from __future__ import annotations

import json
from pathlib import Path

from twoddoc.catalog import get_catalog

OUT = Path("twoddoc/catalog/data/grep_targets.json")


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
    reqs = cat._requirements          # {code: {mandatory, mandatory_alt, facultative, forbidden}}
    doctypes = cat._doc_types["01"]

    out: dict[str, dict] = {}
    for code in sorted(reqs):
        r = reqs[code]
        obligation = {}
        for fid in r.get("mandatory", []):
            obligation[fid] = "O"
        for fid in r.get("mandatory_alt", []):
            obligation[fid] = "O*"
        for fid in r.get("facultative", []):
            obligation.setdefault(fid, "F")

        eligible = sorted(f for f in obligation if not f.startswith("0"))  # §3.4

        fields, strong, weak = {}, [], []
        for fid in eligible:
            di = cat.data_id(fid)
            signal = est_signal(di)
            (strong if signal == "strong" else weak).append(fid)
            fields[fid] = {
                "label": di.label if di else None,
                "kind": di.kind if di else None,
                "obligation": obligation[fid],
                "signal": signal,
            }

        interchangeable = sorted(
            f for f in r.get("mandatory_alt", []) if not f.startswith("0")
        )
        types = doctypes.get(code, {}).get("types") or []
        out[code] = {
            "label": types[0] if types else None,
            "strong": strong,
            "weak": weak,
            # O* fields are interchangeable (match any one); the spec footnotes
            # group them but the grouping is not machine-modelled, so all O* of a
            # type are reported as a single best-effort group.
            "interchangeable_groups": [interchangeable] if interchangeable else [],
            "fields": fields,
        }

    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} ({len(out)} document types)")


if __name__ == "__main__":
    main()
