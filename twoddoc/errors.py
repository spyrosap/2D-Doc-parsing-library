"""Exception hierarchy for the twoddoc library."""

from __future__ import annotations


class TwoDDocError(Exception):
    """Base class for all 2D-Doc errors."""


class DetectionError(TwoDDocError):
    """Raised when no 2D-Doc DataMatrix can be located/decoded on a document."""


class DecodeError(TwoDDocError):
    """Raised when a codec (C40 / Base32 / Base256 / ASCII) fails."""


class HeaderError(TwoDDocError):
    """Raised when the header is malformed or its version is unsupported."""


class MessageError(TwoDDocError):
    """Raised when the message zone cannot be parsed against the catalog."""


class CatalogError(TwoDDocError):
    """Raised when catalog resources are missing or inconsistent."""


class TrustError(TwoDDocError):
    """Base class for trust/verification problems."""


class TSLError(TrustError):
    """Raised when the Trusted Service List cannot be fetched or parsed."""


class CertificateRetrievalError(TrustError):
    """Raised when the signing certificate cannot be located/fetched."""


class VerificationError(TrustError):
    """Raised when signature/chain verification cannot be performed."""
