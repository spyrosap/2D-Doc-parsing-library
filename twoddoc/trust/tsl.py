"""ANTS Trusted Service List (TSL) download and parsing (§5.1).

The list (ETSI TS 119 612) is published at:
``https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml``

For each ``TrustServiceProvider`` we extract:

* the **AC identifier** (``TSPInformation/TSPTradeName/Name``, e.g. ``FR03``);
* the AC's certificate **publication URIs** (``TSPInformationURI/URI``);
* the inline **CA certificates** of its granted CA/PKC services
  (``ServiceDigitalIdentity/.../X509Certificate``) — these are the trust anchors.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from lxml import etree

from ..errors import TSLError

TSL_URL = "https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml"
_CA_PKC = "Svctype/CA/PKC"
_GRANTED = ("inaccord", "granted")  # ETSI "granted" status keywords
_DEFAULT_TTL = 7 * 24 * 3600  # 1 week


def _ln(tag: str) -> str:
    return f"*[local-name()='{tag}']"


@dataclass
class TSLEntry:
    """One trust-service provider, keyed by its 2D-Doc AC identifier."""

    ac_id: str
    name: str
    info_uris: list[str] = field(default_factory=list)
    ca_certificates: list[x509.Certificate] = field(default_factory=list)


@dataclass
class TSL:
    """Indexed view of the trusted list."""

    entries: dict[str, TSLEntry]

    def get(self, ac_id: str) -> TSLEntry | None:
        return self.entries.get(ac_id)

    def all_ca_certificates(self) -> list[x509.Certificate]:
        out: list[x509.Certificate] = []
        for e in self.entries.values():
            out.extend(e.ca_certificates)
        return out


def parse_tsl(xml: bytes) -> TSL:
    """Parse trusted-list XML bytes into a :class:`TSL`."""
    try:
        root = etree.fromstring(xml)
    except etree.XMLSyntaxError as exc:
        raise TSLError(f"invalid TSL XML: {exc}") from exc

    entries: dict[str, TSLEntry] = {}
    for tsp in root.xpath(f".//{_ln('TrustServiceProvider')}"):
        names = tsp.xpath(
            f".//{_ln('TSPInformation')}/{_ln('TSPTradeName')}/{_ln('Name')}/text()"
        )
        ac_id = next((n.strip() for n in names if n.strip()), None)
        if not ac_id:
            continue
        tsp_names = tsp.xpath(
            f".//{_ln('TSPInformation')}/{_ln('TSPName')}/{_ln('Name')}/text()"
        )
        info_uris = [
            u.strip()
            for u in tsp.xpath(f".//{_ln('TSPInformationURI')}/{_ln('URI')}/text()")
            if u.strip()
        ]

        ca_certs: list[x509.Certificate] = []
        for svc in tsp.xpath(f".//{_ln('TSPService')}"):
            stype = "".join(svc.xpath(f".//{_ln('ServiceTypeIdentifier')}/text()"))
            status = "".join(svc.xpath(f".//{_ln('ServiceStatus')}/text()"))
            if _CA_PKC not in stype:
                continue
            if not any(k in status for k in _GRANTED):
                continue
            for b64 in svc.xpath(f".//{_ln('X509Certificate')}/text()"):
                try:
                    der = base64.b64decode("".join(b64.split()))
                    ca_certs.append(x509.load_der_x509_certificate(der))
                except Exception:  # noqa: BLE001 - skip malformed certs
                    continue

        entry = entries.get(ac_id)
        if entry is None:
            entries[ac_id] = TSLEntry(
                ac_id=ac_id,
                name=next((n.strip() for n in tsp_names if n.strip()), ac_id),
                info_uris=list(dict.fromkeys(info_uris)),
                ca_certificates=ca_certs,
            )
        else:
            entry.ca_certificates.extend(ca_certs)
            for u in info_uris:
                if u not in entry.info_uris:
                    entry.info_uris.append(u)
    if not entries:
        raise TSLError("no trust-service providers found in TSL")
    return TSL(entries=entries)


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / "tsl_signed.xml"


def load_tsl(
    *,
    url: str = TSL_URL,
    cache_dir: str | Path | None = None,
    ttl: int = _DEFAULT_TTL,
    force_refresh: bool = False,
) -> TSL:
    """Load the TSL, using an on-disk cache with a TTL.

    Network access is only used when the cache is missing/stale.
    """
    if cache_dir is None:
        cache_dir = Path.home() / ".cache" / "twoddoc"
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = _cache_path(cache_dir)

    fresh = (
        cache.exists()
        and not force_refresh
        and (time.time() - cache.stat().st_mtime) < ttl
    )
    if fresh:
        return parse_tsl(cache.read_bytes())

    try:
        import httpx

        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        cache.write_bytes(resp.content)
        return parse_tsl(resp.content)
    except Exception as exc:  # noqa: BLE001
        if cache.exists():  # fall back to a stale cache if the network fails
            return parse_tsl(cache.read_bytes())
        raise TSLError(f"could not fetch TSL from {url}: {exc}") from exc
