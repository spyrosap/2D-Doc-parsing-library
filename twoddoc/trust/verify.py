"""Signature, chain and revocation verification (§3.5, §5.1).

* **Signature** — the 2D-Doc signature is a raw ``r||s`` ECDSA value (X9.62);
  we re-encode it as DER and verify it over the data zone with the curve's
  matching hash (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
* **Chain + revocation + validity** — built/validated with
  ``pyhanko-certvalidator`` against the TSL CA trust anchors, evaluated at the
  document's signature date, with CRL/OCSP revocation when enabled.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, time, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from ..model import TwoDDoc, VerificationResult

_HASH_BY_CURVE = {
    "secp256r1": hashes.SHA256,
    "secp384r1": hashes.SHA384,
    "secp521r1": hashes.SHA512,
}


def verify_signature(cert: Certificate, signed_data: bytes, raw_sig: bytes) -> bool:
    """Verify a raw ``r||s`` ECDSA signature; raise ``InvalidSignature`` if bad."""
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise InvalidSignature("certificate key is not ECDSA")
    if not raw_sig or len(raw_sig) % 2 != 0:
        raise InvalidSignature(f"unexpected signature length {len(raw_sig)}")
    half = len(raw_sig) // 2
    r = int.from_bytes(raw_sig[:half], "big")
    s = int.from_bytes(raw_sig[half:], "big")
    der = utils.encode_dss_signature(r, s)
    hash_cls = _HASH_BY_CURVE.get(pub.curve.name, hashes.SHA256)
    pub.verify(der, signed_data, ec.ECDSA(hash_cls()))
    return True


def _validate_chain(
    leaf: Certificate,
    anchors: list[Certificate],
    moment: datetime | None,
    result: VerificationResult,
) -> None:
    """Build/validate the path to a TSL anchor, evaluated at ``moment``.

    The signing certificate of a past document may have expired since; we
    therefore validate the chain *at the document's signature date* so that a
    cert that was valid when it signed is accepted (§5.1 step 6). Revocation is
    handled separately at the current time.
    """
    try:
        from asn1crypto import x509 as ax
        from pyhanko_certvalidator import CertificateValidator, ValidationContext
    except ImportError as exc:  # pragma: no cover
        result.errors.append(f"pyhanko-certvalidator unavailable: {exc}")
        return

    if not anchors:
        result.errors.append("no TSL trust anchor for this AC")
        return

    roots = [ax.Certificate.load(c.public_bytes(Encoding.DER)) for c in anchors]
    leaf_a = ax.Certificate.load(leaf.public_bytes(Encoding.DER))
    ctx = ValidationContext(
        trust_roots=roots,
        allow_fetching=False,         # revocation is checked separately (current time)
        revocation_mode="soft-fail",
        moment=moment,
    )
    validator = CertificateValidator(leaf_a, validation_context=ctx)
    try:
        path = _run_validate(validator)
        result.chain_valid = True
        anchor = path.first
        result.trust_anchor = anchor.subject.human_friendly if anchor else None
    except Exception as exc:  # noqa: BLE001 - surface the reason
        result.errors.append(f"chain validation failed: {exc}")


def _check_revocation(leaf: Certificate, result: VerificationResult) -> None:
    """Current-time revocation check via the certificate's CRL distribution point.

    Per §5.1 step 5 a revoked certificate invalidates the seal regardless of the
    signature date. We fetch the CRL and check the serial; OCSP is not required.
    """
    try:
        dps = leaf.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
    except x509.ExtensionNotFound:
        result.errors.append("no CRL distribution point in certificate")
        return
    urls = [
        name.value
        for dp in dps
        if dp.full_name
        for name in dp.full_name
        if str(name.value).startswith("http")
    ]
    import httpx

    last_exc: Exception | None = None
    for url in urls:
        try:
            resp = httpx.get(url, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            try:
                crl = x509.load_der_x509_crl(resp.content)
            except ValueError:
                crl = x509.load_pem_x509_crl(resp.content)
            revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
            result.not_revoked = revoked is None
            if revoked is not None:
                result.errors.append(f"certificate revoked on {revoked.revocation_date_utc}")
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
    result.errors.append(f"revocation check failed: {last_exc}")


def _run_validate(validator):
    """Call pyhanko's validator across sync/async API variants."""
    if hasattr(validator, "validate_usage"):
        try:
            return validator.validate_usage(set())
        except TypeError:
            pass
    return asyncio.run(validator.async_validate_usage(set()))


def verify(
    doc: TwoDDoc,
    leaf_cert: Certificate,
    ca_certificates: list[Certificate],
    *,
    check_revocation: bool = True,
) -> VerificationResult:
    """Verify ``doc``'s signature and certificate chain.

    ``leaf_cert`` is the signing certificate; ``ca_certificates`` are the TSL
    trust anchors for the document's AC.
    """
    result = VerificationResult()
    result.certificate_subject = leaf_cert.subject.rfc4514_string()

    # 1. signature over the data zone. The encoded data zone and the bytes
    # actually signed can differ by one separator (§3.4/§3.5); try each candidate.
    candidates = doc.signed_data_candidates or [doc.signed_data]
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            verify_signature(leaf_cert, candidate, doc.signature.raw)
            result.signature_valid = True
            break
        except InvalidSignature as exc:
            last_error = exc
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            break
    if not result.signature_valid and last_error is not None:
        result.errors.append(f"signature invalid: {last_error}")

    # 2. chain trust, validated at the document's signature date
    sig_date = doc.header.signature_date
    moment = (
        datetime.combine(sig_date, time(12, 0), tzinfo=timezone.utc)
        if sig_date is not None
        else None
    )
    _validate_chain(leaf_cert, ca_certificates, moment, result)

    # 3. revocation, checked now (a revoked cert invalidates regardless of date)
    if check_revocation:
        _check_revocation(leaf_cert, result)
    else:
        result.not_revoked = True  # not checked

    # 4. validity period must contain the document's signature date (§5.1 step 6)
    if doc.header.signature_date is not None:
        try:
            nb = leaf_cert.not_valid_before_utc.date()
            na = leaf_cert.not_valid_after_utc.date()
            result.within_validity = nb <= doc.header.signature_date <= na
        except Exception:  # noqa: BLE001 - older cryptography without *_utc
            nb = leaf_cert.not_valid_before.date()
            na = leaf_cert.not_valid_after.date()
            result.within_validity = nb <= doc.header.signature_date <= na

    return result
