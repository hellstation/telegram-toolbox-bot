"""High-level domain security report service for bot handlers."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from cleaner.security.analyzer import FullAnalysisResult, run_full_analysis
from cleaner.security.config import SecurityConfig, load_security_config
from cleaner.security.report_html import render_html_report
from cleaner.security.validators import normalize_domain

logger = logging.getLogger(__name__)

_last_call_by_user: dict[int, float] = {}


@dataclass
class DomainReport:
    domain: str
    html: str
    caption: str
    result: FullAnalysisResult


def check_domain_rate_limit(user_id: int, rate_limit_seconds: float | None = None) -> float | None:
    """Return remaining seconds if limited, else None and record the call."""
    cfg_limit = rate_limit_seconds
    if cfg_limit is None:
        cfg_limit = load_security_config().rate_limit_seconds
    now = time.monotonic()
    last = _last_call_by_user.get(user_id, 0.0)
    elapsed = now - last
    if elapsed < cfg_limit:
        return round(cfg_limit - elapsed, 1)
    _last_call_by_user[user_id] = now
    return None


def build_caption(result: FullAnalysisResult) -> str:
    risk = result.risk
    tech_names = [result.tech_info.display_name(name) for name, _cat in result.tech_info.detected]
    tech_str = ", ".join(tech_names) if tech_names else "not detected"

    total_cves = sum(len(r.entries) for r in result.cve_results)

    ssl_note = ""
    if result.ssl_info.has_ssl:
        if result.ssl_info.is_expired:
            ssl_note = " ⚠️ SSL expired"
        elif result.ssl_info.is_expiring_soon:
            ssl_note = f" ⚠️ SSL expires in {result.ssl_info.days_until_expiry}d"

    return (
        f"📋 Report ready: {result.domain}\n\n"
        f"{risk.emoji} Risk: {risk.level} (score {risk.score})\n"
        f"🛠 Tech: {tech_str}\n"
        f"🌍 Subdomains: {len(result.subdomains)}\n"
        f"🔒 SSL/TLS:{ssl_note if ssl_note else ' ok'}\n"
        f"🛡 CVEs found: {total_cves}\n"
        f"⚔️ Attack paths: {len(result.attack_paths)}\n\n"
        f"Full report is in the attached HTML file 👇"
    )


async def analyze_domain_report(
    raw_input: str,
    config: SecurityConfig | None = None,
) -> DomainReport | str:
    """
    Analyze a domain and return DomainReport, or an error string.
    Caller should send HTML as document + caption.
    """
    domain = normalize_domain(raw_input)
    if not domain:
        return (
            "❌ Could not parse domain. Send e.g. example.com or https://example.com"
        )

    cfg = config or load_security_config()
    logger.info("Starting domain security analysis for %s", domain)

    result = await run_full_analysis(
        domain=domain,
        nvd_api_key=cfg.nvd_api_key,
        max_cve_results=cfg.max_cve_results,
        timeout=cfg.request_timeout,
        shodan_api_key=cfg.shodan_api_key,
        censys_api_id=cfg.censys_api_id,
        censys_api_secret=cfg.censys_api_secret,
    )
    html = render_html_report(result)
    return DomainReport(
        domain=domain,
        html=html,
        caption=build_caption(result),
        result=result,
    )
