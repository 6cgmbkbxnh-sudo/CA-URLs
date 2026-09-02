#!/usr/bin/env python3
"""
Build CRL / OCSP / CA Issuers URL lists for Mozilla-trusted CA certificates
from the public CCADB API and the official CCADB PEM downloads.

Requirements:
    python3 -m pip install requests cryptography

Run:
    python3 mozilla_pki_urls.py

Outputs:
    mozilla-pki-urls/
      mozilla_pki_urls.csv
      crl_urls.txt
      ocsp_urls.txt
      ca_issuers_urls.txt
      mozilla_ca_certificates.csv
      summary.txt

The script uses:
  - CCADB AllCertificateRecords REST API
  - official CCADB "All Certificate PEMs Year" CSV endpoint

No CCADB login/token is required.
"""

from __future__ import annotations

import csv
import io
import re
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes


API = "https://ccadb.my.site.com/services/apexrest/v1/allcertificaterecords"
PEM_URL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"

OUT = Path("mozilla-pki-urls")
CACHE = OUT / "cache"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "mozilla-pki-url-export/1.0",
    "Accept": "*/*",
})

TIMEOUT = 120


def request_json(url, payload):
    for attempt in range(1, 4):
        try:
            r = SESSION.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
                timeout=TIMEOUT,
            )
            if r.status_code >= 400:
                raise RuntimeError(
                    f"HTTP {r.status_code}: {r.text[:1000]}"
                )
            return r.json()
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry {attempt}/3: {e}", file=sys.stderr)
            time.sleep(attempt * 2)


def download(url, path):
    if path.exists() and path.stat().st_size > 0:
        print(f"Using cache: {path}")
        return path.read_bytes()

    print(f"Downloading: {url}")
    for attempt in range(1, 4):
        try:
            with SESSION.get(url, timeout=TIMEOUT, stream=True) as r:
                r.raise_for_status()
                tmp = path.with_suffix(path.suffix + ".part")
                with tmp.open("wb") as f:
                    for chunk in r.iter_content(1024 * 1024):
                        if chunk:
                            f.write(chunk)
                tmp.replace(path)
                return path.read_bytes()
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry {attempt}/3: {e}", file=sys.stderr)
            time.sleep(attempt * 2)


def norm(v):
    return re.sub(r"[^a-z0-9]", "", str(v or "").lower())


def flatten(obj, prefix=""):
    """Yield (path, value) for every scalar in a JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            yield from flatten(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, obj


def find_value(obj, *wanted):
    wanted = {norm(x) for x in wanted}
    for path, value in flatten(obj):
        leaf = path.split(".")[-1]
        leaf = re.sub(r"\[\d+\]$", "", leaf)
        if norm(leaf) in wanted:
            return value
    return None


def find_all_values(obj, *wanted):
    wanted = {norm(x) for x in wanted}
    result = []
    for path, value in flatten(obj):
        leaf = path.split(".")[-1]
        leaf = re.sub(r"\[\d+\]$", "", leaf)
        if norm(leaf) in wanted:
            result.append(value)
    return result


def urls_from_value(value):
    if value is None:
        return []
    if isinstance(value, list):
        out = []
        for x in value:
            out.extend(urls_from_value(x))
        return out
    if isinstance(value, dict):
        out = []
        for x in value.values():
            out.extend(urls_from_value(x))
        return out
    return re.findall(r'https?://[^\s"<>\\\]]+', str(value))


def parse_date(value):
    if not value:
        return None
    s = str(value).strip()
    for fmt in (
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(s[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def current_record(record):
    vf = find_value(record, "ValidFrom", "Valid From (GMT)", "Valid From")
    vt = find_value(record, "ValidTo", "Valid To (GMT)", "Valid To")
    now = datetime.now(timezone.utc)

    d = parse_date(vf)
    if d and d > now:
        return False
    d = parse_date(vt)
    if d and d < now:
        return False
    return True


def mozilla_trusted(record):
    status = str(find_value(record, "MozillaStatus", "Mozilla Status") or "").strip().lower()
    rtype = str(find_value(
        record, "CertificateRecordType", "Certificate Record Type", "RecordType"
    ) or "").strip().lower()

    if rtype.startswith("root"):
        return status == "included"
    if rtype.startswith("intermediate"):
        return status == "trusted"
    return False


def get_records(year):
    page = 1
    all_records = []

    while page:
        payload = {
            "filters": {
                "notBeforeYear": year,
                "PageNumber": page,
            },
            "fieldSets": [
                "PertainingToCertificatesIssued",
            ],
        }

        data = request_json(API, payload)

        records = data.get("Data", [])
        if not isinstance(records, list):
            raise RuntimeError(
                f"Unexpected CCADB response: Data is {type(records).__name__}"
            )

        all_records.extend(records)

        pagination = (data.get("Meta") or {}).get("Pagination") or {}
        next_page = pagination.get("NextPageNumber", 0)

        print(
            f"  year={year}: page={page}, records={len(records)}, "
            f"next={next_page}"
        )

        if not next_page:
            break
        page = int(next_page)

    return all_records


def record_metadata(record):
    return {
        "ccadb_id": find_value(record, "CCADBUniqueID", "RecordID"),
        "certificate_name": find_value(record, "CertificateName", "Name"),
        "record_type": find_value(record, "CertificateRecordType", "RecordType"),
        "mozilla_status": find_value(record, "MozillaStatus", "Mozilla Status"),
        "valid_from": find_value(record, "ValidFrom", "Valid From (GMT)", "Valid From"),
        "valid_to": find_value(record, "ValidTo", "Valid To (GMT)", "Valid To"),
        "sha256": find_value(record, "SHA256Fingerprint", "SHA-256 Fingerprint"),
        "parent_sha256": find_value(record, "ParentSHA256Fingerprint"),
    }


def add_url(store, typ, url, meta, source):
    url = str(url).strip().rstrip(".,;)")
    if not url.startswith(("http://", "https://")):
        return
    host = urlparse(url).hostname or ""
    if not host:
        return

    key = (typ, url.lower())
    if key not in store:
        store[key] = {
            "type": typ,
            "url": url,
            "hostname": host.lower(),
            "certificate_sha256": meta.get("sha256") or "",
            "certificate_name": meta.get("certificate_name") or "",
            "record_type": meta.get("record_type") or "",
            "mozilla_status": meta.get("mozilla_status") or "",
            "source": source,
        }


def parse_pem_csv(data, wanted_sha256, meta_by_sha):
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise RuntimeError("CCADB PEM CSV has no header")

    fields = reader.fieldnames
    pem_field = next(
        (f for f in fields if "pem" in norm(f) and "certificate" in norm(f)),
        None,
    )
    if pem_field is None:
        pem_field = next((f for f in fields if "pem" in norm(f)), None)

    fp_field = next(
        (f for f in fields if "sha256" in norm(f) or "fingerprint" in norm(f)),
        None,
    )

    if pem_field is None:
        raise RuntimeError(
            "Could not find PEM column in CCADB PEM CSV. Columns: "
            + ", ".join(fields)
        )

    found = 0

    for row in reader:
        pem = row.get(pem_field, "")
        if "BEGIN CERTIFICATE" not in pem:
            continue

        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except Exception:
            continue

        sha = cert.fingerprint(hashes.SHA256()).hex().upper()

        if fp_field:
            declared = re.sub(r"[^0-9A-Fa-f]", "", row.get(fp_field, "")).upper()
            if declared and declared != sha:
                continue

        if sha not in wanted_sha256:
            continue

        meta = meta_by_sha.get(sha, {})
        found += 1

        # CRL Distribution Points
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            )
            for dp in ext.value:
                if not dp.full_name:
                    continue
                for gn in dp.full_name:
                    if isinstance(gn, x509.UniformResourceIdentifier):
                        add_url(
                            URLS, "CRL", gn.value, meta,
                            "X.509 CRL Distribution Points"
                        )
        except x509.ExtensionNotFound:
            pass

        # Authority Information Access
        try:
            ext = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            )
            for access in ext.value:
                loc = access.access_location
                if not isinstance(loc, x509.UniformResourceIdentifier):
                    continue

                if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    add_url(
                        URLS, "OCSP", loc.value, meta,
                        "X.509 AIA / OCSP"
                    )
                elif access.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    add_url(
                        URLS, "CA_ISSUERS", loc.value, meta,
                        "X.509 AIA / CA Issuers"
                    )
        except x509.ExtensionNotFound:
            pass

    return found


URLS = OrderedDict()


def main():
    OUT.mkdir(exist_ok=True)
    CACHE.mkdir(exist_ok=True)

    current_year = datetime.now(timezone.utc).year

    # Public Mozilla-trusted CA records can span many decades.  CCADB supports
    # 1990..2100. We use decade partitioning through the API to avoid hundreds
    # of tiny requests, but PEM downloads are done only for years actually
    # represented by selected records.
    selected = []

    print("=== CCADB / Mozilla PKI URL collector ===")
    print("API:", API)
    print()

    # The API documentation explicitly supports decade filters.
    for decade in range(1990, current_year + 1, 10):
        print(f"Fetching CCADB decade {decade}...")
        page = 1

        while page:
            payload = {
                "filters": {
                    "notBeforeDecade": decade,
                    "PageNumber": page,
                },
                "fieldSets": [
                    "PertainingToCertificatesIssued",
                ],
            }

            data = request_json(API, payload)
            records = data.get("Data", [])

            if not isinstance(records, list):
                raise RuntimeError("CCADB API: Data is not a list")

            for record in records:
                if mozilla_trusted(record) and current_record(record):
                    selected.append(record)

                    meta = record_metadata(record)

                    # CRL URLs directly from CCADB.
                    crl_fields = find_all_values(
                        record,
                        "JSONArrayOfAllFullCRLURLs",
                        "JSONArrayOfPartitionedCRLs",
                    )

                    for value in crl_fields:
                        for u in urls_from_value(value):
                            add_url(URLS, "CRL", u, meta, "CCADB API")

            pagination = (data.get("Meta") or {}).get("Pagination") or {}
            next_page = pagination.get("NextPageNumber", 0)

            print(
                f"  page={page}: {len(records)} records; "
                f"selected total={len(selected)}; next={next_page}"
            )

            page = int(next_page) if next_page else 0

    # De-duplicate selected certificates by SHA256.
    by_sha = {}
    for record in selected:
        meta = record_metadata(record)
        sha = re.sub(r"[^0-9A-Fa-f]", "", meta.get("sha256") or "").upper()
        if len(sha) == 64:
            by_sha[sha] = meta

    print()
    print(f"Selected current Mozilla CA records: {len(selected)}")
    print(f"Unique certificates by SHA-256:       {len(by_sha)}")

    # Save certificate inventory.
    cert_fields = [
        "ccadb_id", "certificate_name", "record_type", "mozilla_status",
        "valid_from", "valid_to", "sha256", "parent_sha256",
    ]
    with (OUT / "mozilla_ca_certificates.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.DictWriter(f, fieldnames=cert_fields)
        w.writeheader()
        for meta in sorted(by_sha.values(), key=lambda x: (x["record_type"] or "", x["certificate_name"] or "")):
            w.writerow(meta)

    # Download official CCADB PEM CSVs only for years represented by selected
    # certificates. The official resources page documents this endpoint.
    years = sorted({
        parse_date(meta.get("valid_from")).year
        for meta in by_sha.values()
        if parse_date(meta.get("valid_from"))
    })

    print()
    print("PEM years:", ", ".join(map(str, years)))

    for year in years:
        cache_file = CACHE / f"AllCertificatePEMs_{year}.csv"
        data = download(PEM_URL.format(year=year), cache_file)
        print(f"Parsing PEM dataset {year} ({len(data) / 1024 / 1024:.1f} MiB)...")
        found = parse_pem_csv(data, set(by_sha), by_sha)
        print(f"  matched certificates: {found}")

    # Write final URL files.
    rows = sorted(
        URLS.values(),
        key=lambda x: (x["type"], x["hostname"], x["url"].lower())
    )

    with (OUT / "mozilla_pki_urls.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        fields = [
            "type", "url", "hostname", "certificate_sha256",
            "certificate_name", "record_type", "mozilla_status", "source",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    for typ, filename in (
        ("CRL", "crl_urls.txt"),
        ("OCSP", "ocsp_urls.txt"),
        ("CA_ISSUERS", "ca_issuers_urls.txt"),
    ):
        values = sorted({
            row["url"] for row in rows if row["type"] == typ
        }, key=str.lower)
        (OUT / filename).write_text(
            "\n".join(values) + ("\n" if values else ""),
            encoding="utf-8",
        )

    counts = {}
    for row in rows:
        counts[row["type"]] = counts.get(row["type"], 0) + 1

    summary = [
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        f"Selected CCADB records: {len(selected)}",
        f"Unique certificates: {len(by_sha)}",
        f"Unique CRL URLs: {counts.get('CRL', 0)}",
        f"Unique OCSP URLs: {counts.get('OCSP', 0)}",
        f"Unique CA Issuers URLs: {counts.get('CA_ISSUERS', 0)}",
        f"Unique total URLs: {len(rows)}",
    ]
    (OUT / "summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )

    print()
    print("=== DONE ===")
    for line in summary:
        print(line)
    print()
    print(f"Output: {OUT.resolve()}")


if __name__ == "__main__":
    main()
