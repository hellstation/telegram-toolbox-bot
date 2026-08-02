"""crt.sh Certificate Transparency: subdomains + certificate emails."""
import asyncio
import json
import logging
import re
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
MAX_SUBDOMAINS = 40
MAX_EMAILS = 25


@dataclass
class CrtshInfo:
    subdomains: list[str] = field(default_factory=list)
    certificate_emails: list[str] = field(default_factory=list)


async def get_crtsh_info(domain: str, timeout: int = 15) -> CrtshInfo:
    """Passive CT lookup via crt.sh. On failure returns empty lists."""
    params = {"q": f"%.{domain}", "output": "json"}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            async with session.get(CRTSH_URL, params=params) as resp:
                if resp.status != 200:
                    logger.warning(f"crt.sh returned status {resp.status} for {domain}")
                    return CrtshInfo()
                raw = await resp.text()
                if not raw.strip():
                    return CrtshInfo()
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning(f"crt.sh returned invalid JSON for {domain}")
                    return CrtshInfo()
    except asyncio.TimeoutError:
        logger.warning(f"crt.sh timeout for {domain}")
        return CrtshInfo()
    except Exception as e:
        logger.warning(f"crt.sh lookup failed for {domain}: {e}")
        return CrtshInfo()

    if not isinstance(data, list):
        return CrtshInfo()

    found_subs: set[str] = set()
    found_emails: set[str] = set()
    email_re = re.compile(r"[A-Za-z0-9._%+\-]+@" + re.escape(domain), re.I)

    for entry in data:
        name_value = entry.get("name_value", "") or ""
        for match in email_re.findall(name_value):
            found_emails.add(match.lower())
        for line in name_value.split("\n"):
            sub = line.strip().lower().lstrip("*.").rstrip(".")
            if not sub or sub == domain:
                continue
            if sub.endswith("." + domain):
                found_subs.add(sub)

    return CrtshInfo(
        subdomains=sorted(found_subs)[:MAX_SUBDOMAINS],
        certificate_emails=sorted(found_emails)[:MAX_EMAILS],
    )


async def get_subdomains(domain: str, timeout: int = 15) -> list[str]:
    """Backward-compatible helper used by older call sites."""
    info = await get_crtsh_info(domain, timeout=timeout)
    return info.subdomains
