#!/usr/bin/env python3
"""Build the 2D-Doc catalog JSON resources from the ANTS spec text.

Usage:
    pdftotext -layout ants_2d-doc_cabspec_v334.pdf spec.txt
    python tools/build_catalog.py spec.txt twoddoc/catalog/data

Parses:
* §7  (DI definitions, perimeter C40 '01')  -> data_ids.json
* §6.1/§6.2 (document types)                -> document_types.json
* §8  (mandatory/optional per doc type)     -> requirements.json
* a small perimeters.json is written from constants.

The result is meant to be hand-verified against the PDF; this script does the
bulk transcription so the numbers/labels are mechanically faithful.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DI_START = re.compile(r"^\s{0,4}([0-9A-Z]{2})\*?\s+(\S.*?)\s*$")
FIELD = re.compile(r"^\s+(Taille Min\.|Taille Max\.|Type|Description)\s+(.*?)\s*$")
SECTION = re.compile(r"^\s*\d+\.\d+\.")          # e.g. "   7.1."
PAGE_NOISE = re.compile(r"P a g e|Spécifications Techniques|Date :|Pôle Data")


def _next_meaningful(lines: list[str], i: int, end: int) -> str | None:
    """Return the next non-empty, non-noise line after index ``i``."""
    for j in range(i + 1, min(end, len(lines))):
        s = lines[j]
        if s.strip() and not PAGE_NOISE.search(s):
            return s
    return None


def _derive_kind(type_str: str, desc: str) -> str:
    d = desc.lower()
    if "hhmmss" in d:
        return "time"
    if "nombre de jours" in d and "hexad" in d:
        return "date_days2000"
    if "base32" in d:
        return "base32"
    if type_str.strip().lower().startswith("numérique"):
        return "numeric"
    return "text"


def parse_data_ids(lines: list[str], start: int, end: int) -> dict:
    out: dict[str, dict] = {}
    cur: dict | None = None
    cur_id: str | None = None
    field_key: str | None = None

    def flush():
        nonlocal cur, cur_id
        if cur_id and cur is not None:
            cur["kind"] = _derive_kind(cur.get("type", ""), cur.get("description", ""))
            out[cur_id] = cur
        cur, cur_id = None, None

    for idx in range(start, end):
        line = lines[idx].rstrip("\n")
        if not line.strip() or PAGE_NOISE.search(line):
            continue
        if SECTION.match(line):
            field_key = None
            continue
        fm = FIELD.match(line)
        if fm and cur is not None:
            key, val = fm.group(1), fm.group(2)
            if key == "Taille Min.":
                cur["min"] = int(val) if val.strip().isdigit() else 0
                field_key = None
            elif key == "Taille Max.":
                cur["max"] = None if "aucune" in val.lower() else int(re.sub(r"\D", "", val) or 0)
                field_key = None
            elif key == "Type":
                cur["type"] = val.strip()
                field_key = None
            elif key == "Description":
                cur["description"] = val.strip()
                field_key = "description"
            continue
        dm = DI_START.match(line)
        if dm:
            nxt = _next_meaningful(lines, idx, end)
            if nxt and nxt.strip().startswith("Taille Min."):
                flush()
                cur_id = dm.group(1)
                cur = {"label": dm.group(2).strip(), "min": 0, "max": None,
                       "type": "", "description": ""}
                field_key = None
                continue
        # continuation of a wrapped description
        if field_key == "description" and cur is not None and line.startswith(" "):
            cur["description"] += " " + line.strip()
    flush()
    return out


STATUS = re.compile(r"^(O\*?|F\*?|N|-)$")
CODE = re.compile(r"^(0x)?[0-9A-Z]{2}$")


def _trailing_statuses(line: str) -> list[str]:
    out: list[str] = []
    for t in reversed(line.split()):
        if STATUS.match(t):
            out.append(t)
        else:
            break
    out.reverse()
    return out


def _all_statuses(line: str) -> list[str] | None:
    toks = line.split()
    if toks and all(STATUS.match(t) for t in toks):
        return toks
    return None


def parse_requirements(lines: list[str], start: int, end: int) -> dict:
    """Parse §8: per doc-type code -> {mandatory, facultative}.

    Handles wrapped rows where the right-aligned O/F/- status cells land on a
    line of their own (separate from the ID/description line).
    """
    reqs: dict[str, dict[str, list[str]]] = {}
    codes: list[str] = []
    i = start
    while i < end:
        line = lines[i].rstrip("\n")
        i += 1
        if not line.strip() or PAGE_NOISE.search(line):
            continue
        toks = line.split()
        if toks[0] == "ID" and len(toks) > 1 and toks[1].lower().startswith("desc"):
            codes = [t for t in toks[2:] if CODE.match(t)]
            continue
        if not codes:
            continue
        m = re.match(r"^\s*([0-9A-Z]{2})\s+\S", line)
        if not m:
            continue
        di = m.group(1)
        statuses = _trailing_statuses(line)
        if len(statuses) != len(codes):
            # statuses wrapped onto a following standalone line — scan ahead
            statuses = []
            for j in range(i, min(i + 3, end)):
                nxt = lines[j].rstrip("\n")
                if not nxt.strip() or PAGE_NOISE.search(nxt):
                    continue
                found = _all_statuses(nxt)
                if found and len(found) == len(codes):
                    statuses = found
                    break
                if re.match(r"^\s*[0-9A-Z]{2}\s+\S", nxt):
                    break  # reached the next row
        if len(statuses) != len(codes):
            continue  # genuinely ambiguous — skip safely
        for code, st in zip(codes, statuses):
            entry = reqs.setdefault(
                code,
                {"mandatory": [], "mandatory_alt": [], "facultative": [], "forbidden": []},
            )
            if st == "O":
                entry["mandatory"].append(di)        # strictly mandatory
            elif st == "O*":
                entry["mandatory_alt"].append(di)    # mandatory but interchangeable
            elif st.startswith("F"):
                entry["facultative"].append(di)
            elif st == "-":
                entry["forbidden"].append(di)        # interdit for this type
    return reqs


def parse_doc_types(lines: list[str], start: int, end: int, binary: bool) -> dict:
    """Parse §6.x: code -> {date_required, types:[...]}.

    The table is visually laid out: a code + its O/N flag may sit on a line with
    no emitter label (multi-bullet codes), with the ``- label`` bullets on
    surrounding lines. We capture every ``code O/N`` and attach bullets to the
    most recent code (best-effort for display labels).
    """
    out: dict[str, dict] = {}
    last_code: str | None = None
    row = re.compile(r"(?:^|\s)((?:0x)?[0-9A-Z]{2})\s+([ON])(?:\s+-\s+(.+?))?\s*$")
    bullet = re.compile(r"-\s+(.+?)\s*$")
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        if not line.strip() or PAGE_NOISE.search(line):
            continue
        m = row.match(line) or row.search(line)
        if m and m.group(2) in ("O", "N"):
            code = m.group(1).replace("0x", "") if binary else m.group(1)
            out[code] = {"date_required": m.group(2) == "O", "types": []}
            if m.group(3):
                out[code]["types"].append(m.group(3).strip())
            last_code = code
            continue
        bm = bullet.search(line)
        if bm and last_code:
            out[last_code]["types"].append(bm.group(1).strip())
    return out


def main() -> None:
    spec = Path(sys.argv[1]).read_text(encoding="utf-8")
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    lines = spec.splitlines()

    def find(pat: str, start: int = 0) -> int:
        rx = re.compile(pat)
        for i in range(start, len(lines)):
            if rx.search(lines[i]):
                return i
        raise SystemExit(f"anchor not found: {pat}")

    # Content-based anchors (robust to layout/line drift)
    a_61 = find(r"6\.1\.\s+Périmètre C40")
    a_62 = find(r"6\.2\.\s+Périmètre Binaire", a_61)
    a_7 = find(r"^7\.\s+Identifiants de données", a_62)
    a_8 = find(r"^8\.\s+Annexe", a_7)
    a_9 = find(r"^9\.\s+Annexe", a_8)

    data_ids = parse_data_ids(lines, a_7, a_8)
    doc_types_c40 = parse_doc_types(lines, a_61, a_62, binary=False)
    doc_types_bin = parse_doc_types(lines, a_62, a_7, binary=True)
    requirements = parse_requirements(lines, a_8, a_9)

    (outdir / "data_ids.json").write_text(
        json.dumps({"01": data_ids}, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "document_types.json").write_text(
        json.dumps({"01": doc_types_c40, "0001": doc_types_bin},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "requirements.json").write_text(
        json.dumps(requirements, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "perimeters.json").write_text(
        json.dumps({"01": {"label": "Périmètre C40 01", "encoding": "C40"},
                    "0001": {"label": "Périmètre Binaire 0x0001", "encoding": "BINARY"}},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"data_ids:        {len(data_ids)}")
    print(f"doc_types c40:   {len(doc_types_c40)}")
    print(f"doc_types bin:   {len(doc_types_bin)}")
    print(f"requirements:    {len(requirements)} doc types")


if __name__ == "__main__":
    main()
