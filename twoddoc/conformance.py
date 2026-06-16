"""Document-level structural conformance against the §8 field requirements.

This is **separate** from signature verification: it does not prove authenticity
(only the signature does), it answers *"does this code carry the field set the
spec requires for its declared document type?"* (§8).

Per document type, each data identifier is:

* ``O``  — strictly mandatory (must be present);
* ``O*`` — mandatory but **interchangeable** (e.g. the full address line ``10`` is
  interchangeable with the split ``11/12/13``); at least one ``O*`` field must
  be present;
* ``F``  — optional;
* ``-``  — forbidden (must not be present).

Note on ``O*``: the spec footnotes group interchangeable fields, but the grouping
is free text we do not model. We therefore apply a best-effort rule — *at least
one* of the type's ``O*`` fields must be present — which is correct for the
common identity group and never rejects a valid common document. The hard
verdict rests on the strict ``O`` and ``-`` rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .catalog import get_catalog

if TYPE_CHECKING:  # pragma: no cover
    from .model import TwoDDoc


@dataclass
class Conformance:
    """Result of the §8 structural conformance check."""

    conformant: bool = False
    document_type: str = ""
    missing_mandatory: list[str] = field(default_factory=list)
    forbidden_present: list[str] = field(default_factory=list)
    interchangeable_satisfied: bool = True
    interchangeable_present: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conformant": self.conformant,
            "document_type": self.document_type,
            "missing_mandatory": self.missing_mandatory,
            "forbidden_present": self.forbidden_present,
            "interchangeable_satisfied": self.interchangeable_satisfied,
            "interchangeable_present": self.interchangeable_present,
            "errors": self.errors,
        }


def check_conformance(doc: "TwoDDoc") -> Conformance:
    """Check ``doc``'s message against the §8 requirements for its document type."""
    cat = get_catalog()
    code = doc.header.document_type
    present = {f.id for f in doc.fields}

    strict = cat.strict_mandatory_ids(code)
    conditional = cat.conditional_ids(code)
    forbidden = cat.forbidden_ids(code)

    result = Conformance(document_type=code)

    if not strict and not conditional and not forbidden:
        # No §8 requirements known for this type (e.g. binary perimeter).
        result.errors.append(f"no requirements defined for document type {code}")
        result.conformant = True  # nothing to violate
        return result

    result.missing_mandatory = sorted(set(strict) - present)
    result.forbidden_present = sorted(set(forbidden) & present)

    if conditional:
        hits = sorted(set(conditional) & present)
        result.interchangeable_present = hits
        result.interchangeable_satisfied = bool(hits)

    result.conformant = (
        not result.missing_mandatory
        and not result.forbidden_present
        and result.interchangeable_satisfied
    )
    return result
