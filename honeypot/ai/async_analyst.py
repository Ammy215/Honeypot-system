"""
AI analyst — HoneyShield v2 (asyncio), direct Google Gemini SDK call, no
LangChain. Originally built against OpenAI (HONEYSHIELD_PROJECT.md section
3 says "drop LangChain, call OpenAI SDK directly") — swapped to Gemini
(google-genai, gemini-2.5-flash) per explicit instruction; same direct-SDK
principle, different provider.

Generates a threat report for one captured attacker from real DB data
only. Anti-hallucination is the core design constraint (section 10 phase 6
test: "confirm it doesn't hallucinate data not in the DB") — the prompt
supplies the complete captured record for the IP and explicitly instructs
the model to report gaps as gaps, never invent detail to fill them.
"""

import logging
from datetime import datetime
from typing import Dict, Optional

from google import genai
from google.genai import types
from google.genai.errors import APIError

import config
from database.db_async import db
from honeypot.detectors.async_correlation import detect_asn_campaigns

logger = logging.getLogger("honeypot.ai.analyst")

_client: Optional[genai.Client] = None

SYSTEM_PROMPT = (
    "You are a cybersecurity threat analyst writing a report for a SOC dashboard "
    "from honeypot capture data. You will be given the complete captured record "
    "for one attacker IP — every connection, login attempt, alert, and enrichment "
    "field that exists for it. Write your report using ONLY this data.\n\n"
    "Rules:\n"
    "- Never invent, assume, or infer a detail that is not explicitly present in "
    "the data below (no invented usernames, tools, locations, or motivations, and "
    "no counts beyond what's given).\n"
    "- If a field is missing, empty, or zero, say so plainly (e.g. \"no login "
    "attempts were captured\") — do not skip the gap silently and do not pad it "
    "with generic speculation.\n"
    "- If the data is sparse, write a short report that reflects that sparseness. "
    "A one-connection attacker with no other activity deserves two or three "
    "sentences, not a padded multi-section profile.\n"
    "- Every number you state (connection counts, attempt counts, scores) must "
    "match a number given to you exactly."
)


def is_available() -> bool:
    return bool(config.GEMINI_API_KEY) and config.GEMINI_API_KEY != "your_key_here"


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(api_key=config.GEMINI_API_KEY, http_options=types.HttpOptions(timeout=30000))
    return _client


async def _gather_context(ip_address: str) -> Optional[Dict]:
    """Pull every real row tied to this IP — nothing here is inferred or summarized."""
    attacker = await db.get_attacker(ip_address)
    if not attacker:
        return None

    connections = await db.list_connections_for_ip(ip_address, limit=50)
    login_attempts = await db.list_login_attempts_for_ip(ip_address, limit=50)
    alerts = await db.list_alerts_for_ip(ip_address, limit=20)

    campaigns = await detect_asn_campaigns()
    campaign = next((c for c in campaigns if ip_address in c["ip_addresses"]), None)

    return {
        "attacker": attacker,
        "connections": connections,
        "login_attempts": login_attempts,
        "alerts": alerts,
        "campaign": campaign,
    }


def _format_context(ctx: Dict) -> str:
    a = ctx["attacker"]
    lines = [
        "ATTACKER PROFILE",
        f"IP Address: {a['ip_address']}",
        f"First Seen: {a.get('first_seen')}",
        f"Last Seen: {a.get('last_seen')}",
        f"Total Connections (recorded): {a.get('total_connections', 0)}",
        f"Country: {a.get('country') or 'not enriched / unknown'}",
        f"City: {a.get('city') or 'not enriched / unknown'}",
        f"ISP: {a.get('isp') or 'not enriched / unknown'}",
        f"ASN: {a.get('asn') or 'not enriched / unknown'}",
        f"AbuseIPDB Score: {a['abuseipdb_score'] if a.get('abuseipdb_score') is not None else 'not checked'}",
        f"OTX Pulse Count: {a.get('otx_pulse_count', 0)}",
        f"Threat Score: {a.get('threat_score', 0)}/100",
        f"Verdict: {a.get('verdict') or 'not yet scored'}",
    ]

    conns = ctx["connections"]
    lines.append(f"\nCONNECTIONS ({len(conns)} shown, most recent first):")
    lines += [f"- service={c['service']} port={c['port']} at={c['connected_at']}" for c in conns] or ["- none recorded"]

    attempts = ctx["login_attempts"]
    lines.append(f"\nLOGIN ATTEMPTS ({len(attempts)} shown, most recent first):")
    lines += [
        f"- service={la['service']} username={la['username']!r} password={la['password']!r} at={la['attempted_at']}"
        for la in attempts
    ] or ["- none recorded"]

    alerts = ctx["alerts"]
    lines.append(f"\nALERTS ({len(alerts)} shown, most recent first):")
    lines += [
        f"- [{al['severity']}] {al['alert_type']} at={al['created_at']} evidence={al['evidence']}" for al in alerts
    ] or ["- none triggered"]

    campaign = ctx["campaign"]
    lines.append("\nCAMPAIGN MEMBERSHIP:")
    if campaign:
        lines.append(
            f"- Part of a detected campaign: ASN={campaign['asn']}, "
            f"{campaign['attacker_count']} coordinated attacker IPs, "
            f"active {campaign['campaign_start']} to {campaign['campaign_end']}"
        )
    else:
        lines.append("- not currently part of any detected multi-IP campaign")

    return "\n".join(lines)


async def generate_attacker_report(ip_address: str) -> Dict:
    """
    Generate and persist a threat report for one attacker. Never raises —
    every failure mode (no key, no data, API error/timeout) returns a
    result dict with error=True and a clear message, so the dashboard can
    display it without crashing or corrupting anything.
    """
    generated_at = datetime.now().isoformat()

    if not is_available():
        return {
            "ip_address": ip_address,
            "report_text": "AI analyst unavailable — GEMINI_API_KEY is not configured.",
            "generated_at": generated_at,
            "error": True,
        }

    context = await _gather_context(ip_address)
    if not context:
        return {
            "ip_address": ip_address,
            "report_text": f"No captured data exists for {ip_address}.",
            "generated_at": generated_at,
            "error": True,
        }

    context_text = _format_context(context)

    try:
        client = _get_client()
        response = await client.aio.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=context_text + "\n\nWrite the threat report now.",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                max_output_tokens=600,
            ),
        )
        report_text = (response.text or "").strip()
        if not report_text:
            raise ValueError("Gemini returned an empty response (possibly blocked by safety filters)")
    except APIError as e:
        logger.error(f"Gemini API error generating report for {ip_address}: {e}")
        return {
            "ip_address": ip_address,
            "report_text": f"AI report generation failed: {e}",
            "generated_at": generated_at,
            "error": True,
        }
    except Exception as e:
        logger.error(f"Unexpected error generating AI report for {ip_address}: {e}")
        return {
            "ip_address": ip_address,
            "report_text": f"AI report generation failed: {e}",
            "generated_at": generated_at,
            "error": True,
        }

    await db.record_ai_report(ip_address, report_text)
    logger.info(f"Generated AI report for {ip_address} ({len(report_text)} chars)")

    return {
        "ip_address": ip_address,
        "report_text": report_text,
        "generated_at": generated_at,
        "model": config.GEMINI_MODEL,
        "error": False,
    }
