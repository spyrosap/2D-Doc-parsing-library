# twoddoc

A Python library to **identify, decode, parse and verify** French **2D-Doc**
codes (ANTS Visible Digital Seal / *Cachet Électronique Visible*) on PDF
documents and images.

It implements the ANTS *Spécifications Techniques des Codes à Barres 2D-DOC*
(CAB v3.3.4) and verifies signatures against the official ANTS Trusted Service
List (TSL).

## What it does

1. **Identify** a 2D-Doc DataMatrix on a PDF (or image).
2. **Decode** the DataMatrix to the raw 2D-Doc byte stream.
3. **Parse** the header + message into structured, typed data (JSON).
4. **Verify** the ECDSA signature *and* the certificate chain against the ANTS
   TSL, including validity period and CRL/OCSP revocation.

Supported: C40 versions 01–04 and the v04 binary header/message/annexe formats.

## Installation

```bash
pip install .
```

The DataMatrix reader depends on the system **libdmtx** library:

```bash
# macOS
brew install libdmtx
# Debian/Ubuntu
sudo apt-get install libdmtx0b
```

Notes:
- On Apple Silicon, ensure the lib is discoverable, e.g.
  `export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libdmtx/lib:$DYLD_LIBRARY_PATH`.
- On Python 3.12+, `pylibdmtx` needs the `distutils` shim — install `setuptools`.

## Usage

### Command line

```bash
twoddoc bill.pdf                 # detect, parse and verify -> JSON
twoddoc bill.pdf --no-verify     # parse only
twoddoc bill.pdf --keystore ./certs   # offline certificate lookup
```

### Library

```python
import twoddoc

# One-call pipeline
for item in twoddoc.process("bill.pdf"):
    print(item["data"])           # parsed fields (each with a `mandatory` flag)
    print(item["conformance"])    # §8 structural conformance for the doc type
    print(item["verification"])   # signature / chain / revocation result

# Building blocks
codes = twoddoc.detect("bill.pdf")        # locate DataMatrix codes
doc = twoddoc.decode(codes[0].raw)        # parse header + message
print(doc.to_json())
result = twoddoc.verify(doc)              # verify against the ANTS TSL
print(result.valid, result.errors)
```

## Conformance vs. verification (two independent checks)

The output separates two distinct questions:

* **`verification`** — *is the seal authentic?* (signature, certificate chain to a
  TSL anchor, validity period, revocation). This is the anti-fraud guarantee.
* **`conformance`** — *does the code carry the field set the spec requires for its
  declared document type?* (§8). Each field also carries a `mandatory` flag.

`conformance` reports `missing_mandatory` (strict `O` fields absent),
`forbidden_present` (`-` fields present), and `interchangeable_satisfied`
(at least one of an `O*` group, e.g. the address line `10` ↔ split `11/12/13`).
A document can be authentic but non-conformant, or well-formed but unsigned —
so the two are reported separately.

## How verification works

* The library downloads and caches the ANTS TSL
  (`https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml`) and indexes
  each Certification Authority by its identifier (e.g. `FR03`), extracting the
  inline **CA certificate** (the trust anchor) and the AC's publication URI.
* The **leaf signing certificate** (identified by the header's cert id) is not in
  the TSL. ACs publish a *collection* of leaf certs and you select the one whose
  subject **CN** equals the cert id. It is resolved by:
  1. an **offline keystore** (a directory of `<ID>.der` certs), or
  2. a **certificate-list bundle** at the TSL `TSPInformationURI` — a
     multipart/PKCS#7 file of all the AC's leaf certs (AriadNEXT/IDnow's
     `pki-2ddoc.der`); select by CN, or
  3. an **RFC 4387 certificate store** (Certigna `FR03`): query by issuer-name
     hash (`search.php?iHash=base64(SHA1(issuer DN))`) to get the bundle, then
     select by CN, or
  4. **fetch-by-URL** `<host>/<ACID><CERTID>.der` as a last resort.
* The signature (raw `r||s`, X9.62) is re-encoded to DER and verified with the
  curve-appropriate hash (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512) over the
  data zone. The chain is validated to a TSL trust anchor **at the document's
  signature date** (so a certificate that has since expired but was valid when
  it signed is accepted, per §5.1 step 6), via `pyhanko-certvalidator`.
  Revocation is checked **at the current time** against the certificate's CRL
  distribution point (a revoked certificate invalidates the seal regardless of
  the signature date, per §5.1 step 5).

### Signed-data reconstruction

The bytes that are signed are *not always identical* to the encoded data zone:
the encoder may drop a `<GS>` separator at the mandatory→facultatif boundary
after a fixed-length field (see §3.4/§3.5 and the §16 reference codes).
Verification therefore tries a small set of reconstructed candidates and accepts
the signature if any matches — robust without weakening security.

## The data catalog

The full catalog of perimeters, document types and ~400 data identifiers is
generated from the spec by `tools/build_catalog.py` into
`twoddoc/catalog/data/*.json`. To regenerate:

```bash
pdftotext -layout ants_2d-doc_cabspec_v334.pdf spec.txt
python tools/build_catalog.py spec.txt twoddoc/catalog/data
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite validates the codecs against the spec's worked examples, header/message
parsing, the catalog, the live TSL structure, and end-to-end signature
verification against the official reference code & certificate (§16).

## Status / limitations

- v01 (Base256 signature, single experimental emitter) parses the header but its
  message/signature split needs the raw codeword stream; signature verification
  for v01 is not implemented.
- Leaf-certificate retrieval is verified end-to-end for AriadNEXT/IDnow
  (bundle) and Certigna `FR03` (RFC 4387 store); other issuers may need a per-AC
  override or the offline keystore.
- Verified `valid: true` end-to-end against real production documents: an ENGIE
  energy bill (AC `FR03`/Certigna) and a DGFiP *avis d'impôt* (AC `FR04`/AriadNEXT).

## Performance

PDFs are rendered at **400 dpi** (needed to resolve dense codes such as DGFiP
*avis d'impôt*) and the DataMatrix scan stops at the **first** code found
(`max_count=1`) on the first page that carries one. A present code is located in
well under a second; the bounded per-page timeout only applies when a page has
no code. Tune via `detect(..., dpi=…, timeout_ms=…, max_count=…)`.
