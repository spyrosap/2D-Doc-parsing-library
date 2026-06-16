"""Data model for parsed and verified 2D-Doc codes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any


class Encoding(str, Enum):
    """Wire encoding of a 2D-Doc data zone."""

    C40 = "C40"
    BINARY = "BINARY"


@dataclass
class Header:
    """Parsed 2D-Doc header (§3.3)."""

    marker: str                     # "DC"
    version: int                    # 1..4
    encoding: Encoding
    ca_id: str                      # authority of certification identifier, e.g. "FR03"
    cert_id: str                    # certificate identifier, e.g. "XT4A"
    emission_date: date | None
    signature_date: date | None
    document_type: str              # e.g. "01"
    perimeter: str | None = None    # v03+ (defaults to "01" for v01/02)
    country: str | None = None      # v04 only (ISO-3166-1)
    raw: str = ""                   # the exact header substring (for signing)

    @property
    def identifier(self) -> str:
        """The 8-char certificate identifier (CA id + cert id)."""
        return f"{self.ca_id}{self.cert_id}"


@dataclass
class Field:
    """A single parsed message field (§3.4)."""

    id: str                     # data identifier, e.g. "10"
    label: str                  # human label from the catalog
    raw_value: str | bytes      # value as decoded off the wire
    value: Any                  # type-converted value (date/int/str/bytes/...)
    truncated: bool = False     # ended with <RS>
    # Whether this DI is mandatory for the document type (§8). None when the
    # obligation is unknown/not applicable (e.g. annexe fields).
    mandatory: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        v = self.value
        if isinstance(v, (date,)):
            v = v.isoformat()
        elif isinstance(v, bytes):
            v = v.hex()
        return {
            "id": self.id,
            "label": self.label,
            "value": v,
            "raw": self.raw_value.hex() if isinstance(self.raw_value, bytes) else self.raw_value,
            "mandatory": self.mandatory,
            "truncated": self.truncated,
        }


@dataclass
class Signature:
    """Signature material extracted from a 2D-Doc (§3.5)."""

    raw: bytes                  # the signature bytes (r||s, X9.62)
    encoding: str               # "base32" (v02+) or "base256" (v01)


@dataclass
class TwoDDoc:
    """A fully parsed 2D-Doc."""

    header: Header
    fields: list[Field]
    signature: Signature
    signed_data: bytes          # primary candidate for the signed bytes (header+message)
    # Alternative reconstructions of the signed bytes. The encoded data zone and
    # the bytes actually signed can differ by a separator dropped at the
    # mandatory/facultatif boundary after a fixed-length field (see §3.4/§3.5 and
    # the reference codes in §16). Verification tries each candidate.
    signed_data_candidates: list[bytes] = field(default_factory=list)
    annexe: list[Field] = field(default_factory=list)
    document_label: str | None = None  # resolved doc-type label
    perimeter_label: str | None = None

    def field(self, data_id: str) -> Field | None:
        for f in self.fields:
            if f.id == data_id:
                return f
        return None

    def to_dict(self) -> dict[str, Any]:
        h = self.header
        return {
            "header": {
                "marker": h.marker,
                "version": h.version,
                "encoding": h.encoding.value,
                "ca_id": h.ca_id,
                "cert_id": h.cert_id,
                "identifier": h.identifier,
                "emission_date": h.emission_date.isoformat() if h.emission_date else None,
                "signature_date": h.signature_date.isoformat() if h.signature_date else None,
                "document_type": h.document_type,
                "document_label": self.document_label,
                "perimeter": h.perimeter,
                "perimeter_label": self.perimeter_label,
                "country": h.country,
            },
            "fields": [f.to_dict() for f in self.fields],
            "annexe": [f.to_dict() for f in self.annexe],
            "signature": {
                "encoding": self.signature.encoding,
                "size": len(self.signature.raw),
                "hex": self.signature.raw.hex(),
            },
        }

    def to_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("ensure_ascii", False)
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)


@dataclass
class VerificationResult:
    """Outcome of signature + certificate-chain verification (§5.1)."""

    signature_valid: bool = False
    chain_valid: bool = False
    not_revoked: bool = False
    within_validity: bool = False
    trust_anchor: str | None = None      # CA subject / AC id of the anchor
    certificate_subject: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Overall validity: every check passed."""
        return (
            self.signature_valid
            and self.chain_valid
            and self.not_revoked
            and self.within_validity
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signature_valid": self.signature_valid,
            "chain_valid": self.chain_valid,
            "not_revoked": self.not_revoked,
            "within_validity": self.within_validity,
            "trust_anchor": self.trust_anchor,
            "certificate_subject": self.certificate_subject,
            "errors": self.errors,
        }
