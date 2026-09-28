"""Daily security checks for CVEs, HTTP security headers, and DNS/SSL."""

from datetime import datetime, timedelta, timezone
import json
import socket
import ssl
from pathlib import Path

import dns.resolver
import requests


# Change these three values for the systems you own or are authorized to scan.
KEYWORD = "wordpress"
URL = "https://example.com"
DOMAIN = "example.com"

DATA_DIR = Path(__file__).parent / "data"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def load(name):
    """Load a saved JSON value, returning an empty value when none exists."""
    path = DATA_DIR / name
    if not path.exists():
        return [] if name == "cves.json" else {}
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return [] if name == "cves.json" else {}


def save(name, data):
    """Save JSON data in the repository's data directory."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with (DATA_DIR / name).open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, sort_keys=True)
        file.write("\n")


def diff(old, new):
    """Return added, removed, and changed values between two dictionaries."""
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    added = {key: new[key] for key in new.keys() - old.keys()}
    removed = {key: old[key] for key in old.keys() - new.keys()}
    changed = {
        key: {"old": old[key], "new": new[key]}
        for key in old.keys() & new.keys()
        if old[key] != new[key]
    }
    return {"added": added, "removed": removed, "changed": changed}


def check_cves(keyword):
    """Query NVD and return CVEs that were not present in the previous run."""
    previous = load("cves.json")
    previous_ids = {item.get("id") for item in previous if isinstance(item, dict)}

    response = requests.get(
        NVD_API,
        params={"keywordSearch": keyword, "resultsPerPage": 2000},
        timeout=20,
    )
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])
    current = []

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        metrics = cve.get("metrics", {})
        severity = None
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(metric_name):
                severity = metrics[metric_name][0].get("cvssData", {}).get("baseSeverity")
                if severity:
                    break
        current.append({"id": cve.get("id"), "description": description, "severity": severity})

    current = [item for item in current if item["id"]]
    save("cves.json", current)
    return [item for item in current if item["id"] not in previous_ids]


def check_headers(url):
    """Fetch a URL and return security-header changes since the previous scan."""
    previous = load("headers.json")
    response = requests.get(url, timeout=20, allow_redirects=True)
    response.raise_for_status()
    current = {name: response.headers[name] for name in SECURITY_HEADERS if name in response.headers}
    changes = diff(previous, current)
    save("headers.json", current)
    return changes


def check_dns_ssl(domain):
    """Check DNS records and certificate expiry, returning changes and warnings."""
    previous = load("dns_ssl.json")
    current = {"A": [], "MX": [], "TXT": [], "certificate_expiry": None}
    resolver = dns.resolver.Resolver()

    for record_type in ("A", "MX", "TXT"):
        try:
            answers = resolver.resolve(domain, record_type, lifetime=10)
            if record_type == "MX":
                current[record_type] = sorted(str(answer) for answer in answers)
            elif record_type == "TXT":
                current[record_type] = sorted(
                    "".join(part.decode() if isinstance(part, bytes) else part for part in answer.strings)
                    for answer in answers
                )
            else:
                current[record_type] = sorted(str(answer) for answer in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            current[record_type] = []

    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=domain) as secure_socket:
            certificate = secure_socket.getpeercert()
    expiry = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z")
    current["certificate_expiry"] = expiry.replace(tzinfo=timezone.utc).isoformat()

    changes = diff(previous, current)
    expiry_date = datetime.fromisoformat(current["certificate_expiry"])
    warning = None
    if expiry_date < datetime.now(timezone.utc) + timedelta(days=30):
        warning = f"Certificate expires soon: {current['certificate_expiry']}"
    save("dns_ssl.json", current)
    return {"changes": changes, "warning": warning}


def main():
    """Run all checks and print a report even when one check fails."""
    print(f"Security watch report for {datetime.now(timezone.utc).isoformat()}")

    try:
        cves = check_cves(KEYWORD)
        print(f"\nCVEs: {len(cves)} new result(s)")
        for cve in cves:
            print(f"- {cve['id']} [{cve['severity'] or 'severity unavailable'}]: {cve['description']}")
    except (requests.RequestException, ValueError, OSError) as error:
        print(f"\nCVEs: ERROR - {error}")

    try:
        header_changes = check_headers(URL)
        print(f"\nHeaders ({URL}): {json.dumps(header_changes, indent=2)}")
    except (requests.RequestException, ValueError, OSError) as error:
        print(f"\nHeaders ({URL}): ERROR - {error}")

    try:
        dns_result = check_dns_ssl(DOMAIN)
        print(f"\nDNS/SSL ({DOMAIN}): {json.dumps(dns_result, indent=2)}")
    except (dns.exception.DNSException, OSError, ssl.SSLError, ValueError) as error:
        print(f"\nDNS/SSL ({DOMAIN}): ERROR - {error}")


if __name__ == "__main__":
    main()
