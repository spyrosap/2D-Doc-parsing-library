"""Resolve the leaf signing certificate for a 2D-Doc (§5.1 step 4).

The leaf certificate (identified by the header's CA id + cert id) is not in the
TSL. Strategies, in priority order:

1. **Offline keystore** — look the certificate up by its identifier in a local
   directory of harvested certs (``<ID>.der`` / ``<ID>.cer``).
2. **Local cache** — a previously fetched ``<ACID><CERTID>.der``.
3. **RFC 4387 store** (e.g. Certigna FR03) — when the AC's ``TSPInformationURI``
   is an HTTP certificate store (``search.php?iHash=…``), query it by the issuer
   name hash to obtain the bundle of certs issued by the CA, then select the one
   whose subject CN equals the cert id.
4. **Fetch by URL** — derive ``<host>/<ACID><CERTID>.der`` from the AC's info URI
   (AriadNEXT/ANTS convention) and download it. Per-AC overrides supported.

The CA trust anchors are the inline CA certificates from the matching TSL entry.
"""

from __future__ import annotations

import base64
import email
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from ..errors import CertificateRetrievalError
from ..model import Header
from .tsl import TSL, TSLEntry

# Optional per-AC URL builders: ac_id -> (ca_id, cert_id, entry) -> url
UrlBuilder = Callable[[str, str, TSLEntry], str]


def _is_rfc4387_store(entry: TSLEntry) -> bool:
    return any(("search.php" in u or "iHash" in u) for u in entry.info_uris)


def _subject_cn(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _select_by_cn(certs: list[x509.Certificate], cert_id: str) -> x509.Certificate | None:
    for cert in certs:
        if _subject_cn(cert) == cert_id:
            return cert
    return None


def _name_hash(cert: x509.Certificate) -> str:
    """RFC 4387 name hash: base64(SHA-1(DER(subject name))), unpadded."""
    digest = hashlib.sha1(cert.subject.public_bytes()).digest()
    return base64.b64encode(digest).decode().rstrip("=")


def _load_certs(content: bytes, content_type: str) -> list[x509.Certificate]:
    """Parse a cert-store response: multipart/mixed, PKCS#7, or a single DER/PEM."""
    ctype = (content_type or "").lower()
    if "multipart" in ctype:
        raw = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + content
        msg = email.message_from_bytes(raw)
        certs: list[x509.Certificate] = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            body = part.get_payload(decode=True)
            if body:
                certs.extend(_load_single(body))
        return certs
    return _load_single(content)


def _load_single(data: bytes) -> list[x509.Certificate]:
    for loader in (
        lambda d: [x509.load_der_x509_certificate(d)],
        lambda d: [x509.load_pem_x509_certificate(d)],
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    ):
        try:
            return list(loader(data))
        except Exception:  # noqa: BLE001
            continue
    return []


def _default_leaf_url(ca_id: str, cert_id: str, entry: TSLEntry) -> str | None:
    """Derive the leaf URL by swapping the filename of the AC's info URI."""
    if not entry.info_uris:
        return None
    base = entry.info_uris[0]
    parsed = urlparse(base)
    # strip query and the last path segment, then append <ACID><CERTID>.der
    path = parsed.path.rsplit("/", 1)[0]
    return f"{parsed.scheme}://{parsed.netloc}{path}/{ca_id}{cert_id}.der"


@dataclass
class CertResolver:
    """Locate the leaf signing certificate and its CA anchors."""

    tsl: TSL
    keystore_dir: str | Path | None = None
    cache_dir: str | Path | None = None
    url_overrides: dict[str, UrlBuilder] = field(default_factory=dict)
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if self.cache_dir is None:
            self.cache_dir = Path.home() / ".cache" / "twoddoc" / "certs"
        self.cache_dir = Path(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.keystore_dir is not None:
            self.keystore_dir = Path(self.keystore_dir)

    # --- public API ----------------------------------------------------------

    def resolve(self, header: Header) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Return (leaf certificate, CA trust anchors) for ``header``."""
        ca_id, cert_id = header.ca_id, header.cert_id
        entry = self.tsl.get(ca_id)
        anchors = list(entry.ca_certificates) if entry else []

        leaf = self._from_keystore(ca_id, cert_id) or self._from_cache(ca_id, cert_id)
        if leaf is None and entry is not None:
            if _is_rfc4387_store(entry):
                # Certigna-style: RFC 4387 store, queried by issuer-name hash.
                leaf = self._fetch_store(ca_id, cert_id, entry, anchors)
            else:
                # AriadNEXT/ANTS-style: the info URI is a published certificate
                # collection (bundle); select the leaf by subject CN.
                leaf = self._fetch_bundle(ca_id, cert_id, entry) or self._fetch(
                    ca_id, cert_id, entry
                )
        if leaf is None:
            raise CertificateRetrievalError(
                f"could not locate signing certificate for {ca_id}{cert_id}"
            )
        return leaf, anchors

    # --- strategies ----------------------------------------------------------

    def _identifier_candidates(self, ca_id: str, cert_id: str) -> list[str]:
        return [f"{ca_id}{cert_id}", cert_id, f"{ca_id}_{cert_id}"]

    def _load_cert(self, raw: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(raw)
        except ValueError:
            return x509.load_pem_x509_certificate(raw)

    def _from_keystore(self, ca_id: str, cert_id: str) -> x509.Certificate | None:
        if not self.keystore_dir or not Path(self.keystore_dir).is_dir():
            return None
        for ident in self._identifier_candidates(ca_id, cert_id):
            for ext in (".der", ".cer", ".crt", ".pem"):
                path = Path(self.keystore_dir) / f"{ident}{ext}"
                if path.exists():
                    return self._load_cert(path.read_bytes())
        return None

    def _from_cache(self, ca_id: str, cert_id: str) -> x509.Certificate | None:
        path = Path(self.cache_dir) / f"{ca_id}{cert_id}.der"
        if path.exists():
            return self._load_cert(path.read_bytes())
        return None

    def _fetch(
        self, ca_id: str, cert_id: str, entry: TSLEntry | None
    ) -> x509.Certificate | None:
        if entry is None:
            return None
        builder = self.url_overrides.get(ca_id)
        url = builder(ca_id, cert_id, entry) if builder else _default_leaf_url(
            ca_id, cert_id, entry
        )
        if not url:
            return None
        try:
            import httpx

            resp = httpx.get(url, timeout=self.timeout, follow_redirects=True)
            resp.raise_for_status()
            content = resp.content
            cert = self._load_cert(content)
        except Exception as exc:  # noqa: BLE001
            raise CertificateRetrievalError(
                f"failed to fetch leaf cert for {ca_id}{cert_id} from {url}: {exc}"
            ) from exc
        (Path(self.cache_dir) / f"{ca_id}{cert_id}.der").write_bytes(content)
        return cert

    def _cache(self, ca_id: str, cert_id: str, cert: x509.Certificate) -> x509.Certificate:
        (Path(self.cache_dir) / f"{ca_id}{cert_id}.der").write_bytes(
            cert.public_bytes(Encoding.DER)
        )
        return cert

    def _fetch_bundle(
        self, ca_id: str, cert_id: str, entry: TSLEntry
    ) -> x509.Certificate | None:
        """Download the AC's published certificate collection; select by CN.

        AriadNEXT/IDnow publish a ``pki-2ddoc.der`` *certificate list* (a
        multipart/PKCS#7 bundle of all leaf certs); the TSL info URI points at it.
        """
        import httpx

        for uri in entry.info_uris:
            try:
                resp = httpx.get(uri, timeout=self.timeout, follow_redirects=True)
                resp.raise_for_status()
                certs = _load_certs(resp.content, resp.headers.get("content-type", ""))
            except Exception:  # noqa: BLE001
                continue
            cert = _select_by_cn(certs, cert_id)
            if cert is not None:
                return self._cache(ca_id, cert_id, cert)
        return None

    def _fetch_store(
        self, ca_id: str, cert_id: str, entry: TSLEntry,
        anchors: list[x509.Certificate],
    ) -> x509.Certificate | None:
        """RFC 4387 store: query by issuer-name hash, select by subject CN."""
        if not anchors:
            return None
        import httpx

        base = entry.info_uris[0].split("?", 1)[0]
        last_exc: Exception | None = None
        for anchor in anchors:
            url = f"{base}?iHash={quote(_name_hash(anchor), safe='')}"
            try:
                resp = httpx.get(url, timeout=self.timeout, follow_redirects=True)
                resp.raise_for_status()
                certs = _load_certs(resp.content, resp.headers.get("content-type", ""))
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue
            cert = _select_by_cn(certs, cert_id)
            if cert is not None:
                return self._cache(ca_id, cert_id, cert)
        if last_exc is not None:
            raise CertificateRetrievalError(
                f"failed to query cert store for {ca_id}{cert_id}: {last_exc}"
            ) from last_exc
        return None
