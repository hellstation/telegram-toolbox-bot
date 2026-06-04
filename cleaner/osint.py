import asyncio
import hashlib
import ipaddress
import importlib.resources
import logging
import os
import re
import shutil
import socket
import smtplib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

import aiohttp
import phonenumbers
import whois
from phonenumbers import carrier, geocoder, timezone


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
MAIGRET_TOP_SITES = int(os.getenv("MAIGRET_TOP_SITES", "500"))
MAIGRET_TIMEOUT = int(os.getenv("MAIGRET_TIMEOUT", "20"))
MAIGRET_MAX_CONNECTIONS = int(os.getenv("MAIGRET_MAX_CONNECTIONS", "100"))
MAIGRET_PARSE_PROFILES = os.getenv("MAIGRET_PARSE_PROFILES", "0").strip().lower() in {"1", "true", "yes", "on"}

PHONE_TYPE_MAP = {
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    phonenumbers.PhoneNumberType.PAGER: "Pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}


TOOL_TITLES = {
    "username": "👤 Username Scan",
    "ip": "🌐 IP Tracker",
    "phone": "📞 Phone Tracker",
    "vehicle": "🚗 Dutch Vehicle Scanner",
    "smtp": "📧 SMTP",
    "connections": "🔗 Connections",
    "domain": "🌍 WHOIS / Domain",
}

TOOL_PROMPTS = {
    "username": "👤 Send username to scan:",
    "ip": "🌐 Send IP address:",
    "phone": "📞 Send phone number with country code, e.g. +31612345678:",
    "vehicle": "🚗 Send Dutch license plate, e.g. AB-12-CD:",
    "smtp": "📧 Send email address:",
    "connections": "🔗 Send email address:",
    "domain": "🌍 Send domain or IP:",
}


async def run_tool(tool: str, target: str) -> str:
    target = target.strip()
    if not target:
        return "❌ Empty query."

    runners = {
        "username": scan_username,
        "ip": track_ip,
        "phone": inspect_phone,
        "vehicle": inspect_vehicle,
        "smtp": validate_smtp,
        "connections": inspect_connections,
        "domain": inspect_domain,
    }
    runner = runners.get(tool)
    if not runner:
        return "❌ Unknown OSINT tool."

    try:
        return await runner(target)
    except Exception as exc:
        return f"❌ OSINT check failed: {exc}"


async def scan_username(username: str) -> str:
    return await scan_username_maigret(username)


async def scan_username_maigret(username: str) -> str:
    try:
        from maigret import search as maigret_search
        from maigret.sites import MaigretDatabase
    except ImportError as exc:
        raise RuntimeError("maigret package is not installed") from exc

    db_path = importlib.resources.files("maigret").joinpath("resources/data.json")
    db = MaigretDatabase().load_from_path(str(db_path))
    sites = db.ranked_sites_dict(top=MAIGRET_TOP_SITES)
    results = await maigret_search(
        username=username,
        site_dict=sites,
        logger=logging.getLogger("maigret"),
        timeout=MAIGRET_TIMEOUT,
        is_parsing_enabled=MAIGRET_PARSE_PROFILES,
        max_connections=MAIGRET_MAX_CONNECTIONS,
        no_progressbar=True,
    )
    return format_maigret_username_results(username, results, len(sites))


def format_maigret_username_results(username: str, results: dict[str, Any], checked_count: int) -> str:
    grouped = {
        "found": [],
        "maybe": [],
        "not_found": [],
        "error": [],
    }

    for site_name, result in results.items():
        if not result:
            continue
        status = result.get("status")
        group = maigret_status_group(status)
        grouped[group].append(
            {
                "site": site_name,
                "url": result.get("url_user") or result.get("url_main") or "",
                "http_status": result.get("http_status"),
                "rank": result.get("rank"),
                "ids_data": result.get("ids_data") or {},
            }
        )

    lines = [
        f"👤 Maigret Username Scan: {username}",
        "",
        "Summary:",
        f"Checked: {checked_count}",
        f"✅ Found: {len(grouped['found'])}",
        f"🟡 Maybe/blocked: {len(grouped['maybe'])}",
        f"➖ Not found: {len(grouped['not_found'])}",
        f"⚠️ Error: {len(grouped['error'])}",
        f"Settings: top={MAIGRET_TOP_SITES}, timeout={MAIGRET_TIMEOUT}s, parsing={'on' if MAIGRET_PARSE_PROFILES else 'off'}",
    ]

    append_maigret_group(lines, "FOUND", "✅", grouped["found"], limit=None)
    append_maigret_group(lines, "MAYBE / BLOCKED", "🟡", grouped["maybe"], limit=50)
    append_maigret_group(lines, "ERROR", "⚠️", grouped["error"], limit=50)

    lines.append("")
    lines.append("NOT FOUND")
    if grouped["not_found"]:
        lines.append(f"{len(grouped['not_found'])} site(s), hidden to keep chat readable.")
    else:
        lines.append("None")
    return "\n".join(lines)


def maigret_status_group(status: Any) -> str:
    if hasattr(status, "is_found") and status.is_found():
        return "found"

    status_text = str(status).lower()
    if "claimed" in status_text or "found" in status_text:
        return "found"
    if any(marker in status_text for marker in ("unknown", "illegal", "blocked", "captcha")):
        return "maybe"
    if any(marker in status_text for marker in ("available", "not_found", "not found")):
        return "not_found"
    return "error"


def append_maigret_group(
    lines: list[str],
    title: str,
    icon: str,
    items: list[dict[str, Any]],
    limit: Optional[int],
) -> None:
    lines.append("")
    lines.append(title)
    if not items:
        lines.append("None")
        return

    shown = items if limit is None else items[:limit]
    for item in shown:
        details = []
        if item.get("http_status"):
            details.append(f"HTTP {item['http_status']}")
        if item.get("rank"):
            details.append(f"rank {item['rank']}")
        suffix = f" ({', '.join(details)})" if details else ""
        url = item.get("url") or "-"
        lines.append(f"{icon} {item['site']}: {url}{suffix}")
        ids_data = item.get("ids_data")
        if isinstance(ids_data, dict):
            compact_data = compact_ids_data(ids_data)
            if compact_data:
                lines.append(f"Data: {compact_data}")

    if limit is not None and len(items) > limit:
        lines.append(f"... and {len(items) - limit} more")


def compact_ids_data(ids_data: dict[str, Any]) -> str:
    parts = []
    for key, value in ids_data.items():
        if value in (None, "", [], {}):
            continue
        text = ", ".join(str(item) for item in value[:3]) if isinstance(value, list) else str(value)
        text = text.replace("\n", " ").strip()
        if text:
            parts.append(f"{key}={text[:120]}")
        if len(parts) >= 3:
            break
    return "; ".join(parts)


async def track_ip(ip_address: str) -> str:
    url = f"https://ipinfo.io/{ip_address}/json"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status != 200:
                return f"❌ ipinfo.io returned status {response.status}"
            data = await response.json()

    return format_mapping(f"🌐 IP Information: {ip_address}", data)


async def inspect_phone(phone_number: str) -> str:
    def run() -> dict[str, str]:
        parsed = phonenumbers.parse(phone_number, None)
        return {
            "Number (E.164)": phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.E164,
            ),
            "Location": geocoder.description_for_number(parsed, "en"),
            "Region Code": phonenumbers.region_code_for_number(parsed),
            "Timezone(s)": ", ".join(timezone.time_zones_for_number(parsed)),
            "Carrier": carrier.name_for_number(parsed, "en") or "Unknown",
            "Type": PHONE_TYPE_MAP.get(phonenumbers.number_type(parsed), "Unknown"),
            "Valid": str(phonenumbers.is_valid_number(parsed)),
            "Possible": str(phonenumbers.is_possible_number(parsed)),
        }

    try:
        data = await asyncio.to_thread(run)
    except phonenumbers.NumberParseException as exc:
        return f"❌ Cannot parse phone number: {exc}"
    return format_mapping(f"📞 Phone Intelligence: {phone_number}", data)


async def inspect_vehicle(plate: str) -> str:
    normalized = plate.replace("-", "").replace(" ", "").upper()
    url = f"https://opendata.rdw.nl/resource/m9d7-ebf2.json?kenteken={normalized}"
    headers = {"User-Agent": "Telegram-Toolbox-Bot/1.0"}

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status != 200:
                return f"❌ RDW API returned status {response.status}"
            payload = await response.json()

    if not payload:
        return f"❌ Vehicle not found for plate {normalized}"

    car = payload[0]
    data = analyze_vehicle(car)
    return format_mapping(f"🚗 Vehicle Intel: {normalized}", data)


async def lookup_whois(target: str) -> str:
    def normalize(value: Any) -> str:
        if value is None:
            return "Unknown"
        if isinstance(value, list):
            seen: set[str] = set()
            items: list[str] = []
            for item in value:
                text = str(item).strip()
                if text and text not in seen:
                    seen.add(text)
                    items.append(text)
            return ", ".join(items) if items else "Unknown"
        return str(value).strip() or "Unknown"

    def run() -> dict[str, str]:
        record = whois.whois(target.strip().lower())
        if not record or not record.domain_name:
            return {}
        return {
            "Domain": normalize(record.domain_name),
            "Registrar": normalize(record.registrar),
            "Organization": normalize(getattr(record, "org", None)),
            "Country": normalize(getattr(record, "country", None)),
            "State": normalize(getattr(record, "state", None)),
            "Created": normalize(record.creation_date),
            "Updated": normalize(record.updated_date),
            "Expires": normalize(record.expiration_date),
            "Name Servers": normalize(record.name_servers),
            "Status": normalize(record.status),
            "Emails": normalize(record.emails),
            "DNSSEC": normalize(getattr(record, "dnssec", None)),
        }

    try:
        data = await asyncio.to_thread(run)
    except whois.parser.PywhoisError as exc:
        return f"❌ WHOIS error: {exc}"
    if not data:
        return f"❌ No WHOIS data found for {target}"
    return format_mapping(f"🌍 WHOIS: {target}", data)


async def validate_smtp(email: str) -> str:
    email = email.strip()
    result = {
        "Email": email,
        "Format": "Invalid",
        "Domain": "Unknown",
        "MX": "Not found",
        "SMTP": "Not checked",
        "Details": "",
    }

    if not EMAIL_RE.match(email):
        result["Details"] = "Invalid email format"
        return format_mapping(f"📧 SMTP Email Validation: {email}", result)

    domain = email.split("@", 1)[1].lower()
    result["Format"] = "Valid"
    result["Domain"] = domain

    mx_hosts = await resolve_mx(domain)
    if not mx_hosts:
        result["SMTP"] = "Unknown"
        result["Details"] = "No MX records found"
        return format_mapping(f"📧 SMTP Email Validation: {email}", result)

    result["MX"] = ", ".join(mx_hosts)
    smtp_status, details = await asyncio.to_thread(smtp_check, email, mx_hosts[0])
    result["SMTP"] = smtp_status
    result["Details"] = details
    return format_mapping(f"📧 SMTP Email Validation: {email}", result)


async def inspect_connections(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return "❌ Invalid email format."

    blackbird_services, blackbird_note = await asyncio.to_thread(run_blackbird, email)
    findings: list[dict[str, str]]
    note: str

    if blackbird_services:
        findings = [
            {
                "source": "Blackbird",
                "status": "confirmed",
                "confidence": "medium",
                "evidence": f"Found {len(blackbird_services)} service match(es)",
                "url": "https://github.com/p1ngul1n0/blackbird",
            }
        ]
        findings.extend(
            {
                "source": f"Blackbird/{service.get('site', 'Unknown')}",
                "status": "confirmed",
                "confidence": "medium",
                "evidence": "Potential account association from Blackbird scan",
                "url": service.get("url", ""),
            }
            for service in blackbird_services[:50]
        )
        note = "Blackbird results are heuristic OSINT matches."
    else:
        async with aiohttp.ClientSession() as session:
            findings = await asyncio.gather(
                check_gravatar(session, email),
                check_github_commits(session, email),
                check_hibp(session, email),
            )
        note = f"{blackbird_note}. Fallback to public-source checks."

    confirmed = sum(1 for item in findings if item.get("status") == "confirmed")
    not_found = sum(1 for item in findings if item.get("status") == "not_found")
    unknown = sum(1 for item in findings if item.get("status") == "unknown")

    lines = [
        f"🔗 Connections: {email}",
        f"Summary: confirmed={confirmed}, not_found={not_found}, unknown={unknown}",
        f"Note: {note}",
        "",
    ]
    for item in findings:
        lines.append(
            f"{status_icon(item.get('status'))} {item.get('source', '-')}: "
            f"{item.get('status', 'unknown')} / {item.get('confidence', '-')}"
        )
        if item.get("evidence"):
            lines.append(f"Evidence: {item['evidence']}")
        if item.get("url"):
            lines.append(f"URL: {item['url']}")
        lines.append("")
    return "\n".join(lines).strip()


async def inspect_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if is_ip_address(domain):
        ip_info_task = asyncio.create_task(track_ip(domain))
        reverse_dns_task = asyncio.create_task(reverse_dns(domain))
        ip_info, hostname = await asyncio.gather(ip_info_task, reverse_dns_task)

        lines = [f"🌍 WHOIS / Domain: {domain}", ""]
        lines.append("Input type: IP address")
        lines.append(f"Reverse DNS: {hostname or 'Not found'}")
        lines.append("")
        lines.append(ip_info)
        return "\n".join(lines)

    whois_task = asyncio.create_task(lookup_whois(domain))
    dns_task = asyncio.create_task(resolve_dns_records(domain))
    crtsh_task = asyncio.create_task(fetch_crtsh_entries(domain))
    http_task = asyncio.create_task(fetch_http_intel(domain))
    whois_result, dns_records, crtsh_entries, http_intel = await asyncio.gather(
        whois_task,
        dns_task,
        crtsh_task,
        http_task,
    )
    emails = extract_certificate_emails(domain, crtsh_entries)
    subdomains = extract_certificate_subdomains(domain, crtsh_entries)

    lines = [f"🌍 WHOIS / Domain: {domain}", ""]
    if whois_result.startswith("❌"):
        lines.append(f"WHOIS: {whois_result}")
    else:
        lines.append(whois_result)
    lines.append("")

    lines.append("DNS records:")
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        values = dns_records.get(record_type, [])
        lines.append(f"{record_type}:")
        if values:
            lines.extend(f"• {value}" for value in values[:12])
            if len(values) > 12:
                lines.append(f"• ... and {len(values) - 12} more")
        else:
            lines.append("• Not found")

    lines.append("")
    lines.append("Subdomains from crt.sh:")
    if subdomains:
        lines.extend(f"• {subdomain}" for subdomain in subdomains[:50])
        if len(subdomains) > 50:
            lines.append(f"• ... and {len(subdomains) - 50} more")
    else:
        lines.append("No subdomains found in crt.sh.")

    lines.append("")
    lines.append("Certificate emails:")
    lines.extend(f"• {email}" for email in emails[:25]) if emails else lines.append("No emails found in crt.sh.")
    if len(emails) > 25:
        lines.append(f"• ... and {len(emails) - 25} more")

    lines.append("")
    lines.append(format_http_intel(http_intel))
    return "\n".join(lines)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def reverse_dns(ip_address: str) -> str:
    def lookup() -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except (OSError, socket.herror):
            return ""
        return hostname

    return await asyncio.to_thread(lookup)


def analyze_vehicle(car: dict[str, Any]) -> dict[str, str]:
    report = {
        "License Plate": car.get("kenteken", "Unknown"),
        "Vehicle": f"{car.get('merk', 'Unknown')} {car.get('handelsbenaming', 'Unknown')}",
        "Vehicle Type": car.get("voertuigsoort", "Unknown"),
        "Body Type": car.get("inrichting", "Unknown"),
        "Primary Color": car.get("eerste_kleur", "Unknown"),
        "Secondary Color": car.get("tweede_kleur", "Unknown"),
        "Fuel Type": car.get("brandstof_omschrijving", "Unknown"),
        "Engine": f"{car.get('aantal_cilinders', 'Unknown')} cyl, {car.get('cilinderinhoud', 'Unknown')}cc",
        "Weight": f"{car.get('massa_ledig_voertuig', 'Unknown')} kg empty / {car.get('toegestane_maximum_massa_voertuig', 'Unknown')} kg max",
        "Seats": str(car.get("aantal_zitplaatsen", "Unknown")),
        "Doors": str(car.get("aantal_deuren", "Unknown")),
        "First Registration": car.get("datum_eerste_toelating", "Unknown"),
        "Current Registration": car.get("datum_tenaamstelling", "Unknown"),
        "APK Expiry": car.get("vervaldatum_apk", "Unknown"),
        "Catalog Price": f"€{car.get('catalogusprijs', 'Unknown')}",
        "BPM Tax": f"€{car.get('bruto_bpm', 'Unknown')}",
        "WAM Insured": car.get("wam_verzekerd", "Unknown"),
        "Export Indicator": car.get("export_indicator", "Unknown"),
        "Taxi Indicator": car.get("taxi_indicator", "Unknown"),
        "Last Mileage Year": str(car.get("jaar_laatste_registratie_tellerstand", "Unknown")),
    }

    risks = []
    if car.get("wam_verzekerd") == "Nee":
        risks.append("Not WAM insured")
    if car.get("export_indicator") == "Ja":
        risks.append("Marked for export")
    if car.get("taxi_indicator") == "Ja":
        risks.append("Commercial taxi use")

    try:
        first_registration = car.get("datum_eerste_toelating", "")
        if first_registration and first_registration != "Unknown":
            age = datetime.now().year - int(str(first_registration)[:4])
            report["Vehicle Age"] = f"{age} years"
            if age > 15:
                risks.append("Very old vehicle (>15 years)")
            elif age > 10:
                risks.append("Old vehicle (>10 years)")
        else:
            report["Vehicle Age"] = "Unknown"
    except Exception:
        report["Vehicle Age"] = "Unknown"

    report["Risk Level"] = "LOW" if not risks else ("MEDIUM" if len(risks) == 1 else "HIGH")
    report["Risk Factors"] = ", ".join(risks) if risks else "None identified"
    report["Data Source"] = "RDW Open Data API (opendata.rdw.nl)"
    return report


async def resolve_mx(domain: str) -> list[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://dns.google/resolve?name={domain}&type=MX",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return []
                data = await response.json()
    except Exception:
        return []

    hosts = []
    for answer in data.get("Answer", []):
        raw = str(answer.get("data", "")).strip()
        parts = raw.split()
        host = parts[-1].rstrip(".") if parts else ""
        if host:
            hosts.append(host)
    return hosts


def smtp_check(email: str, mail_host: str) -> tuple[str, str]:
    try:
        with smtplib.SMTP(mail_host, 25, timeout=10) as server:
            server.ehlo_or_helo_if_needed()
            server.mail("validator@localhost")
            code, message = server.rcpt(email)
    except (OSError, smtplib.SMTPException) as exc:
        return "Unknown", f"SMTP connection failed: {exc}"

    text = message.decode(errors="ignore") if isinstance(message, bytes) else str(message)
    if code in (250, 251):
        return "Valid", f"SMTP accepted recipient ({code}: {text})"
    if code in (550, 551, 553):
        return "Invalid", f"SMTP rejected recipient ({code}: {text})"
    return "Unknown", f"SMTP response {code}: {text}"


async def resolve_a(domain: str) -> list[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://dns.google/resolve?name={domain}&type=A",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return []
                data = await response.json()
    except Exception:
        return []
    return [answer["data"] for answer in data.get("Answer", []) if answer.get("data")]


async def resolve_dns_records(domain: str) -> dict[str, list[str]]:
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
    async with aiohttp.ClientSession() as session:
        tasks = [resolve_dns_record(session, domain, record_type) for record_type in record_types]
        results = await asyncio.gather(*tasks)
    return dict(zip(record_types, results))


async def resolve_dns_record(
    session: aiohttp.ClientSession,
    domain: str,
    record_type: str,
) -> list[str]:
    try:
        async with session.get(
            f"https://dns.google/resolve?name={domain}&type={record_type}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            if response.status != 200:
                return []
            data = await response.json()
    except Exception:
        return []

    values = []
    seen = set()
    for answer in data.get("Answer", []):
        raw = str(answer.get("data", "")).strip()
        if not raw:
            continue
        value = normalize_dns_value(record_type, raw)
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def normalize_dns_value(record_type: str, value: str) -> str:
    value = value.strip()
    if record_type in {"NS", "CAA"}:
        return value.rstrip(".")
    if record_type == "MX":
        parts = value.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[-1].rstrip('.')}"
        return value.rstrip(".")
    if record_type == "TXT":
        return value.replace('" "', "").strip('"')
    return value


def extract_certificate_emails(domain: str, entries: list[dict[str, Any]]) -> list[str]:
    emails: set[str] = set()
    for entry in entries:
        found = re.findall(
            r"[A-Za-z0-9._%+\-]+@" + re.escape(domain),
            entry.get("name_value", ""),
        )
        emails.update(found)
    return sorted(emails)


def extract_certificate_subdomains(domain: str, entries: list[dict[str, Any]]) -> list[str]:
    subdomains: set[str] = set()
    for entry in entries:
        names = str(entry.get("name_value", "")).splitlines()
        for name in names:
            clean_name = name.strip().lower().lstrip("*.").rstrip(".")
            if clean_name and clean_name.endswith(domain) and clean_name != domain:
                subdomains.add(clean_name)
    return sorted(subdomains)


async def fetch_crtsh_entries(domain: str) -> list[dict[str, Any]]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                if response.status != 200:
                    return []
                entries = await response.json(content_type=None)
    except Exception:
        return []
    return entries if isinstance(entries, list) else []


async def fetch_http_intel(domain: str) -> dict[str, Any]:
    for scheme in ("https", "http"):
        result = await fetch_single_http_intel(f"{scheme}://{domain}")
        if result.get("ok"):
            return result
    return {
        "ok": False,
        "url": f"https://{domain}",
        "error": "HTTP/HTTPS request failed",
        "headers": {},
        "cookies": [],
        "technologies": [],
    }


async def fetch_single_http_intel(url: str) -> dict[str, Any]:
    headers = {"User-Agent": "Telegram-Toolbox-Bot/1.0"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=12),
            ) as response:
                body = await response.text(errors="ignore")
                response_headers = {key: value for key, value in response.headers.items()}
                cookies = [cookie.key for cookie in response.cookies.values()]
                return {
                    "ok": True,
                    "url": str(response.url),
                    "status": response.status,
                    "headers": response_headers,
                    "cookies": cookies,
                    "technologies": detect_technologies(response_headers, cookies, body[:200000]),
                }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "error": str(exc),
            "headers": {},
            "cookies": [],
            "technologies": [],
        }


def detect_technologies(headers: dict[str, str], cookies: list[str], body: str) -> list[str]:
    found: set[str] = set()
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
    cookie_text = " ".join(cookies).lower()
    body_text = body.lower()

    signatures = {
        "Cloudflare": ["cloudflare", "__cf_bm", "cf-ray"],
        "nginx": ["server: nginx"],
        "Apache": ["server: apache"],
        "LiteSpeed": ["litespeed"],
        "Vercel": ["vercel", "_vercel"],
        "Netlify": ["netlify", "x-nf-request-id"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "WooCommerce": ["woocommerce"],
        "Shopify": ["shopify", "x-shopid", "_shopify"],
        "Next.js": ["_next/static", "next-router", "x-nextjs"],
        "Nuxt": ["__nuxt", "nuxt"],
        "React": ["react", "react-dom"],
        "Vue": ["vue.js", "__vue", "data-v-"],
        "Angular": ["ng-version", "angular"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Google Analytics": ["google-analytics", "gtag(", "googletagmanager"],
        "Yandex Metrica": ["mc.yandex.ru", "ym("],
        "PHP": ["x-powered-by: php", "phpsessid"],
        "ASP.NET": ["asp.net", "aspxauth"],
    }

    haystack = f"{header_text}\n{cookie_text}\n{body_text}"
    for technology, markers in signatures.items():
        if any(marker in haystack for marker in markers):
            found.add(technology)
    return sorted(found)


def format_http_intel(data: dict[str, Any]) -> str:
    if not data.get("ok"):
        return f"HTTP intel:\nStatus: request failed\nError: {data.get('error', 'Unknown')}"

    interesting_headers = [
        "server",
        "x-powered-by",
        "content-type",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "cf-ray",
        "x-vercel-id",
        "x-cache",
    ]
    headers = data.get("headers", {})
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    lines = [
        "HTTP intel:",
        f"URL: {data.get('url', 'Unknown')}",
        f"Status: {data.get('status', 'Unknown')}",
    ]
    lines.append("Headers:")
    added = False
    for header in interesting_headers:
        value = normalized_headers.get(header)
        if value:
            lines.append(f"• {header}: {value}")
            added = True
    if not added:
        lines.append("• No selected headers found")

    cookies = data.get("cookies", [])
    lines.append("Cookies:")
    lines.extend(f"• {cookie}" for cookie in cookies[:10]) if cookies else lines.append("• Not set")
    if len(cookies) > 10:
        lines.append(f"• ... and {len(cookies) - 10} more")

    technologies = data.get("technologies", [])
    lines.append("Tech stack:")
    lines.extend(f"• {technology}" for technology in technologies) if technologies else lines.append("• Not detected")
    return "\n".join(lines)


def run_blackbird(email: str) -> tuple[list[dict[str, str]], str]:
    if not shutil.which("blackbird"):
        return [], "Blackbird CLI not found in PATH"

    commands = [
        ["blackbird", "--email", email, "--json"],
        ["blackbird", "-e", email, "--json"],
        ["blackbird", email, "--json"],
        ["blackbird", "--email", email],
        ["blackbird", "-e", email],
        ["blackbird", email],
    ]
    last_error = ""

    for command in commands:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except Exception as exc:
            last_error = str(exc)
            continue

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        blob = extract_json_blob(stdout)
        if blob is not None:
            return normalize_blackbird_services(blob), f"Blackbird mode: {' '.join(command)}"

        services = parse_blackbird_text(f"{stdout}\n{stderr}".strip())
        if services:
            return services, f"Blackbird mode: {' '.join(command)}"
        if proc.returncode != 0 and stderr:
            last_error = stderr.strip()

    return [], f"Blackbird run failed: {last_error or 'no parseable results'}"


def extract_json_blob(raw: str) -> Optional[Union[dict[str, Any], list[Any]]]:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass

    candidates = []
    first_obj = raw.find("{")
    last_obj = raw.rfind("}")
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        candidates.append(raw[first_obj : last_obj + 1])
    first_arr = raw.find("[")
    last_arr = raw.rfind("]")
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        candidates.append(raw[first_arr : last_arr + 1])

    for chunk in candidates:
        try:
            return json.loads(chunk)
        except Exception:
            continue
    return None


def normalize_blackbird_services(payload: Union[dict[str, Any], list[Any]]) -> list[dict[str, str]]:
    services = []
    items = payload.items() if isinstance(payload, dict) else enumerate(payload)

    for key, value in items:
        if not isinstance(value, dict):
            continue
        site = str(value.get("site") or value.get("name") or value.get("service") or key)
        url = str(value.get("url") or value.get("link") or "")
        status_text = str(value.get("status", "")).lower()
        found = value.get("found")

        is_found = bool(found) if isinstance(found, bool) else False
        if not is_found and status_text:
            is_found = status_text in {"found", "exists", "valid", "hit", "true"}
        if not is_found and url:
            is_found = True
        if is_found:
            services.append({"site": site, "url": url})
    return services


def parse_blackbird_text(stdout: str) -> list[dict[str, str]]:
    services = []
    pattern = re.compile(
        r"(?i)([A-Za-z0-9 _.-]{2,})\s*[:\-]\s*(found|exists|valid|yes).*(https?://\S+)?"
    )
    for line in stdout.splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        services.append(
            {
                "site": match.group(1).strip(),
                "url": (match.group(3) or "").strip().rstrip(").,;"),
            }
        )
    return services


async def check_gravatar(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                return public_finding("Gravatar", "confirmed", "high", "Avatar exists for exact email hash", url)
            if response.status == 404:
                return public_finding("Gravatar", "not_found", "high", "No avatar for exact email hash", url)
            return public_finding("Gravatar", "unknown", "low", f"Unexpected HTTP status: {response.status}", url)
    except Exception as exc:
        return public_finding("Gravatar", "unknown", "low", f"Request failed: {exc}", url)


async def check_github_commits(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    url = f"https://api.github.com/search/commits?q={email}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Telegram-Toolbox-Bot"}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status != 200:
                return public_finding("GitHub Commits", "unknown", "low", f"GitHub API status: {response.status}", url)
            data = await response.json()
    except Exception as exc:
        return public_finding("GitHub Commits", "unknown", "low", f"Request failed: {exc}", url)

    total = int(data.get("total_count", 0))
    if total > 0:
        return public_finding("GitHub Commits", "confirmed", "high", f"Email found in {total} indexed commit record(s)", url)
    return public_finding("GitHub Commits", "not_found", "high", "No indexed commits with this email", url)


async def check_hibp(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return public_finding(
            "Have I Been Pwned",
            "unknown",
            "high",
            "Skipped: set HIBP_API_KEY to enable this check",
            "https://haveibeenpwned.com/API/v3",
        )

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"hibp-api-key": api_key, "user-agent": "Telegram-Toolbox-Bot"}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status == 404:
                return public_finding("Have I Been Pwned", "not_found", "high", "No breaches found for this email", "https://haveibeenpwned.com/")
            if response.status != 200:
                return public_finding("Have I Been Pwned", "unknown", "low", f"HIBP API status: {response.status}", "https://haveibeenpwned.com/API/v3")
            breaches = await response.json()
    except Exception as exc:
        return public_finding("Have I Been Pwned", "unknown", "low", f"Request failed: {exc}", "https://haveibeenpwned.com/API/v3")

    names = [breach.get("Name", "") for breach in breaches if breach.get("Name")]
    suffix = "..." if len(names) > 8 else ""
    return public_finding(
        "Have I Been Pwned",
        "confirmed",
        "high",
        f"Found in breaches: {', '.join(names[:8])}{suffix}",
        "https://haveibeenpwned.com/",
    )


def public_finding(source: str, status: str, confidence: str, evidence: str, url: str) -> dict[str, str]:
    return {
        "source": source,
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "url": url,
    }


def status_icon(status: Optional[str]) -> str:
    return {
        "confirmed": "✅",
        "not_found": "➖",
        "unknown": "⚠️",
    }.get(status or "", "•")


def format_mapping(title: str, data: dict[str, Any]) -> str:
    lines = [title, ""]
    for key, value in data.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)
