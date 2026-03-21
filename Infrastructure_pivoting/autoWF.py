import requests
import json
import os
import sys
from datetime import datetime, timezone

VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_VT_KEY")
ST_API_KEY = os.environ.get("ST_API_KEY", "YOUR_ST_KEY")
TIMEOUT = 30


def vt_domain_info(domain: str) -> dict:
    """Get domain info from VirusTotal including passive DNS and relationships."""
    headers = {"x-apikey": VT_API_KEY}
    # Domain report
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=headers,
        timeout=TIMEOUT
    )
    resp.raise_for_status()
    # Historical resolutions
    res_resp = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
        headers=headers,
        timeout=TIMEOUT
    )
    res_resp.raise_for_status()
    data = resp.json()
    res_data = res_resp.json()
    dns_history = [
        {
            "ip": r["attributes"]["ip_address"],
            "date": r["attributes"]["date"]
        }
        for r in res_data.get("data", [])
    ]
    return {
        "domain": domain,
        "last_dns_records": data.get("data", {}).get("attributes", {}).get("last_dns_records", []),
        "dns_history": dns_history
    }


def st_reverse_ip(ip: str) -> list:
    """Find all domains that have resolved to an IP (passive DNS reverse)."""
    headers = {"apikey": ST_API_KEY}
    resp = requests.get(
        f"https://api.securitytrails.com/v1/search/list?ipv4={ip}",
        headers=headers,
        timeout=TIMEOUT
    )
    resp.raise_for_status()
    records = resp.json()
    return [r["hostname"] for r in records.get("records", [])]


def st_subdomains(domain: str) -> list:
    """Get all known subdomains for a domain."""
    headers = {"apikey": ST_API_KEY}
    resp = requests.get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers=headers,
        timeout=TIMEOUT
    )
    resp.raise_for_status()
    subs = resp.json().get("subdomains", [])
    return [f"{s}.{domain}" for s in subs]


def crtsh_certificates(domain: str) -> list:
    """Get all certificates issued for a domain and its subdomains."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        certs = resp.json()
    except (requests.RequestException, ValueError) as e:
        print(f"  [WARN] crt.sh query failed for {domain}: {e}")
        return []
    return list(set([
        entry.get("common_name", "")
        for entry in certs
        if entry.get("common_name")
    ]))



def pivot_domain(seed_domain: str) -> dict:
    """
    Full pivot workflow from a seed domain.
    Returns all discovered infrastructure.
    """
    results = {
        "seed": seed_domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "discovered_ips": set(),
        "discovered_domains": set([seed_domain]),
        "subdomains": set(),
        "certificate_names": set()
    }
    print(f"[*] Starting pivot on: {seed_domain}")
    # Step 1: VT domain info + passive DNS
    vt_data = vt_domain_info(seed_domain)
    for record in vt_data.get("dns_history", []):
        ip = record["ip"]
        results["discovered_ips"].add(ip)
        print(f"  [DNS] Historical resolution: {seed_domain} → {ip}")
        # Step 2: Reverse IP pivot for each discovered IP (IPv4 only)
        if ":" in ip:
            print(f"  [SKIP] IPv6 not supported by ST reverse lookup: {ip}")
            continue
        co_hosted = st_reverse_ip(ip)
        for d in co_hosted:
            if d not in results["discovered_domains"]:
                results["discovered_domains"].add(d)
                print(f"  [IP PIVOT] {ip} → {d}")
    # Step 3: Subdomain enumeration
    subs = st_subdomains(seed_domain)
    results["subdomains"].update(subs)
    for sub in subs:
        print(f"  [SUB] {sub}")
    # Step 4: Certificate transparency
    cert_names = crtsh_certificates(seed_domain)
    results["certificate_names"].update(cert_names)
    for cn in cert_names:
        if cn != seed_domain and cn not in results["discovered_domains"]:
            print(f"  [CERT] Found in CT logs: {cn}")
    # Convert sets to sorted lists for output
    results["discovered_ips"] = sorted(results["discovered_ips"])
    results["discovered_domains"] = sorted(results["discovered_domains"])
    results["subdomains"] = sorted(results["subdomains"])
    results["certificate_names"] = sorted(results["certificate_names"])
    return results


if __name__ == "__main__":
    if VT_API_KEY == "YOUR_VT_KEY" or ST_API_KEY == "YOUR_ST_KEY":
        print("ERROR: Set VT_API_KEY and ST_API_KEY env vars before running.")
        sys.exit(1)
    seed = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = pivot_domain(seed)
    print("\n=== PIVOT SUMMARY ===")
    print(json.dumps(result, indent=2))
