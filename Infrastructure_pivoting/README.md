# Infrastructure Pivoting: How CTI Analysts Expand From a Single IOC to a Full Attacker Network

**The field manual for tracing attacker infrastructure — from one domain to dozens.**
By [Andrey Pautov](https://medium.com/@1200km) — March 2026 · 32 min read

---

## Contents

| File | Description |
|------|-------------|
| **Infrastructure Pivoting_...Medium.pdf** | Full article PDF saved from Medium. |
| **[autoWF.py](autoWF.py)** | Automated pivoting tool: seed domain → full infrastructure map via VirusTotal, SecurityTrails, and crt.sh. |

---

## About This Guide

A junior analyst receives a phishing domain and adds it to a blocklist. A senior CTI analyst treats that same domain as a starting point — a thread that, when pulled correctly, unravels an entire attacker infrastructure.

This guide teaches **infrastructure pivoting**: the systematic process of using one known indicator to discover related, previously-unknown attacker infrastructure. Done well, it transforms a single domain into a map of dozens of C2 servers, staging hosts, and supporting infrastructure — most of which the attacker believes is still unknown.

**Why pivoting works:** Attacker infrastructure is expensive to build. Adversaries reuse hosting providers, registration habits, certificate patterns, and naming conventions across campaigns. These reuse patterns are the analyst's most powerful tool.

**Audience:** CTI analysts, threat hunters, incident responders, and detection engineers.

---

## Table of Contents

1. Introduction: Why Infrastructure Pivoting Is a Core CTI Skill
2. The Mental Model: Why Attackers Leave Trails
3. The Pivoting Workflow: Domain → IP → ASN → Certificates → Expanded Infrastructure
4. Pivot Type 1: Domain → IP Resolution
5. Pivot Type 2: Passive DNS — The History Book of the Internet
6. Pivot Type 3: IP → ASN / Hosting Reuse
7. Pivot Type 4: TLS Certificates — The Most Underused Pivot
8. Pivot Type 5: Subdomain Patterns and Enumeration
9. Pivot Type 6: Shodan / Censys / FOFA — Fingerprinting Infrastructure
10. Pivot Type 7: WHOIS and Registration Pattern Analysis
11. The Complete Tooling Stack
12. Full Worked Example: Tracing a C2 Network End-to-End
13. Automating the Workflow with Python
14. Common Pivoting Mistakes and Dead Ends
15. Interview-Ready: Answering "How Do You Discover Attacker Infrastructure?"
16. Quick Reference Cheatsheet
17. Conclusion
18. References and Further Reading

---

## Tool: autoWF.py — Automated Infrastructure Pivot Workflow

`autoWF.py` implements the article's pivoting workflow as a single-command Python script. Given a seed domain, it automatically runs all four pivot stages and returns a structured infrastructure map.

### What it does

**Stage 1 — VirusTotal passive DNS**
Queries the VirusTotal API for the domain's full historical DNS resolution history, extracting every IP the domain has ever resolved to.

**Stage 2 — Reverse IP pivot (SecurityTrails)**
For each discovered IP, queries SecurityTrails reverse DNS to find all other domains that have resolved to the same IP — uncovering co-hosted or reused infrastructure.

**Stage 3 — Subdomain enumeration (SecurityTrails)**
Enumerates all known subdomains for the seed domain, expanding the infrastructure surface area.

**Stage 4 — Certificate transparency (crt.sh)**
Queries crt.sh CT logs for all TLS certificates issued for the domain and its subdomains, surfacing additional hostnames the attacker may have registered.

### Output

Returns a JSON summary with:
- `discovered_ips` — all IPs the seed domain has resolved to
- `discovered_domains` — all co-hosted domains found via reverse IP lookup
- `subdomains` — all known subdomains
- `certificate_names` — all CN/SAN names from CT logs

### Requirements

```
pip install requests
```

API keys (free tiers sufficient for most CTI work):
- **VirusTotal:** [virustotal.com](https://www.virustotal.com) — free API key
- **SecurityTrails:** [securitytrails.com](https://securitytrails.com) — free tier available

### Usage

```bash
export VT_API_KEY=your_virustotal_api_key
export ST_API_KEY=your_securitytrails_api_key

python3 autoWF.py <seed_domain>
```

**Example:**
```bash
python3 autoWF.py malicious-c2.example.com
```

**Example output:**
```
[*] Starting pivot on: malicious-c2.example.com
  [DNS] Historical resolution: malicious-c2.example.com → 185.220.101.45
  [IP PIVOT] 185.220.101.45 → another-c2.example.net
  [SUB] staging.malicious-c2.example.com
  [CERT] Found in CT logs: admin.malicious-c2.example.com

=== PIVOT SUMMARY ===
{
  "seed": "malicious-c2.example.com",
  "discovered_ips": ["185.220.101.45"],
  "discovered_domains": ["another-c2.example.net", "malicious-c2.example.com"],
  "subdomains": ["staging.malicious-c2.example.com"],
  "certificate_names": ["admin.malicious-c2.example.com", "malicious-c2.example.com"]
}
```

### Notes

- IPv6 addresses are skipped for SecurityTrails reverse lookup (API limitation).
- crt.sh failures are non-fatal — the script continues and logs a warning.
- For large infrastructure clusters, SecurityTrails free tier rate limits may apply.
- **Defensive / research use only.** Run against infrastructure you are authorized to investigate.

---

## Source

- **Medium:** [medium.com/@1200km](https://medium.com/@1200km)
- **Evidence cutoff:** March 2026
