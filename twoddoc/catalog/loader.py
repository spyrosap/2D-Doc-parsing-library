"""Load and index the bundled catalog JSON resources.

The resources are produced from the ANTS spec by ``tools/build_catalog.py``:

* ``data_ids.json``       — per perimeter, ``{id: {label, min, max, type, kind, description}}``
* ``document_types.json`` — per perimeter, ``{code: {date_required, types[]}}``
* ``requirements.json``   — ``{doc_type_code: {mandatory[], facultative[]}}``
* ``perimeters.json``     — ``{id: {label, encoding}}``
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from ..errors import CatalogError

_DATA_PKG = "twoddoc.catalog.data"


@dataclass(frozen=True)
class DataId:
    """A data-identifier definition (§7)."""

    id: str
    label: str
    min: int
    max: int | None        # None == unbounded ("Aucune")
    type: str
    kind: str              # "text" | "numeric" | "date_days2000" | "time" | "base32"
    description: str = ""

    @property
    def fixed_length(self) -> bool:
        """True when the field has a single fixed size (no separator needed)."""
        return self.max is not None and self.min == self.max

    @property
    def fixed_size(self) -> int | None:
        return self.max if self.fixed_length else None


def _load(name: str) -> dict:
    try:
        with resources.files(_DATA_PKG).joinpath(name).open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise CatalogError(f"missing catalog resource {name!r}") from exc


class Catalog:
    """In-memory, indexed view over the catalog resources."""

    def __init__(self) -> None:
        self._data_ids = _load("data_ids.json")
        self._doc_types = _load("document_types.json")
        self._requirements = _load("requirements.json")
        self._perimeters = _load("perimeters.json")

    # --- data identifiers ----------------------------------------------------

    def data_id(self, di: str, perimeter: str = "01") -> DataId | None:
        entry = self._data_ids.get(perimeter, {}).get(di)
        if entry is None:
            return None
        return DataId(
            id=di,
            label=entry["label"],
            min=entry.get("min", 0),
            max=entry.get("max"),
            type=entry.get("type", ""),
            kind=entry.get("kind", "text"),
            description=entry.get("description", ""),
        )

    # --- document types ------------------------------------------------------

    def document_type(self, code: str, perimeter: str = "01") -> dict | None:
        return self._doc_types.get(perimeter, {}).get(code)

    def document_label(self, code: str, perimeter: str = "01") -> str | None:
        dt = self.document_type(code, perimeter)
        if not dt:
            return None
        types = dt.get("types") or []
        return types[0] if types else None

    def perimeter_label(self, perimeter: str) -> str | None:
        p = self._perimeters.get(perimeter)
        return p.get("label") if p else None

    # --- requirements (§8) ---------------------------------------------------

    _EMPTY_REQ = {"mandatory": [], "mandatory_alt": [], "facultative": [], "forbidden": []}

    def requirements(self, code: str) -> dict[str, list[str]]:
        return self._requirements.get(code, dict(self._EMPTY_REQ))

    def strict_mandatory_ids(self, code: str) -> list[str]:
        """DIs marked strictly mandatory (``O``) for this document type."""
        return self.requirements(code).get("mandatory", [])

    def conditional_ids(self, code: str) -> list[str]:
        """DIs marked mandatory-but-interchangeable (``O*``)."""
        return self.requirements(code).get("mandatory_alt", [])

    def forbidden_ids(self, code: str) -> list[str]:
        """DIs explicitly forbidden (``-``) for this document type."""
        return self.requirements(code).get("forbidden", [])

    def mandatory_ids(self, code: str) -> list[str]:
        """All DIs that carry a mandatory marking (``O`` or ``O*``)."""
        req = self.requirements(code)
        return req.get("mandatory", []) + req.get("mandatory_alt", [])


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    """Return the process-wide catalog singleton."""
    return Catalog()
