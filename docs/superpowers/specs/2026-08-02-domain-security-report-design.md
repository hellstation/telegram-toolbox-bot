# Domain Security Report Integration

**Date:** 2026-08-02  
**Status:** Approved for implementation  
**Source:** `/Users/sqwrtick/git-code/kkkk` → `telegram-toolbox-bot`

## Goal

Replace OSINT tool **🌍 WHOIS / Domain** with the full Domain Security Analyzer from `kkkk`, delivering an **HTML report file** (same UX as kkkk), enriched with all fields from the current textual WHOIS/Domain output.

## UX

- Entry: existing OSINT button **🌍 WHOIS / Domain**
- **Domain input** → status message → HTML document (`report_<domain>.html`) + short caption (risk, tech, CVE count)
- **IP input** → keep current behaviour (reverse DNS + IP tracker as text)
- Other OSINT tools unchanged

## Architecture

```
cleaner/security/     # ported kkkk modules (package imports)
  analyzer.py         # orchestrator
  report_html.py      # HTML report
  whois/dns/tech/...  # data collectors
cleaner/handlers.py   # domain branch sends document
cleaner/osint.py      # domain runner delegates; IP path stays
```

Config via env: `NVD_API_KEY`, `SHODAN_API_KEY`, `CENSYS_*`, `REQUEST_TIMEOUT`, `MAX_CVE_RESULTS`, `DOMAIN_RATE_LIMIT_SECONDS`.

## Report sections (HTML)

1. Risk gauge  
2. WHOIS — full OSINT field set (Domain, Registrar, Organization, Country, State, Created, Updated, Expires, Name Servers, Status, Emails, DNSSEC)  
3. DNS — A/AAAA/MX/NS/TXT/CAA (+ optional CNAME/SOA), show «Not found» when empty  
4. HTTP intel — URL, status, selected headers, cookies, tech stack  
5. Subdomains (crt.sh)  
6. Certificate emails (crt.sh)  
7. SSL/TLS, Security headers, Ports (optional API), CVE, Attack paths  

## Constraints

- Public data only (no active exploitation)  
- Optional API keys degrade gracefully  
- Bot UI English; HTML report may remain Russian (from kkkk)  
- Dependencies: `dnspython`, `cryptography`  
