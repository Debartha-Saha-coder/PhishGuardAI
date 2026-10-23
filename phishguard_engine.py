"""
PhishGuard AI 2.0 — Detection Engine
=====================================
Transparent, rule-based phishing-indicator analysis for email/SMS text and URLs.

This module is importable by both the Jupyter Notebook and the automated test
suite. It contains no hardcoded credentials and makes no network requests.

All public functions return plain Python dicts so they are trivially
JSON-serialisable.

Usage
-----
    from phishguard_engine import analyze_message, analyze_url, print_report

License / Disclaimer
--------------------
Educational prototype. Not a production security product.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Rule constants
# ---------------------------------------------------------------------------

URGENT_TERMS: List[str] = [
    "act now",
    "immediately",
    "urgent",
    "within 24 hours",
    "account will be suspended",
    "final warning",
    "verify now",
]

CREDENTIAL_TERMS: List[str] = [
    "password",
    "passcode",
    "one-time password",
    "otp",
    "verification code",
    "login credentials",
    "sign in to verify",
]

PAYMENT_TERMS: List[str] = [
    "pay now",
    "payment failed",
    "claim your refund",
    "processing fee",
    "bank details",
    "card details",
    "wire transfer",
]

LINK_PATTERN: re.Pattern = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"\']+")

# Threshold constants — documented here so tests and the notebook share them.
SCORE_MEDIUM_THRESHOLD = 25
SCORE_HIGH_THRESHOLD = 50
MAX_MESSAGE_LENGTH = 20_000
MAX_URL_LENGTH = 2_048
MAX_EVIDENCE_LENGTH = 240

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    evidence: str,
    explanation: str,
    recommendation: str,
    points: int,
) -> Dict[str, Any]:
    """Build a structured finding dict with truncated evidence."""
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": str(evidence)[:MAX_EVIDENCE_LENGTH],
        "explanation": explanation,
        "recommendation": recommendation,
        "points": points,
    }


def _score_findings(findings: List[Dict[str, Any]]) -> int:
    """
    Sum the highest point contribution for each distinct rule_id.

    This prevents duplicate findings from the same rule inflating the score.
    Result is capped at 100.
    """
    best_by_rule: Dict[str, int] = {}
    for item in findings:
        key = item["rule_id"]
        best_by_rule[key] = max(best_by_rule.get(key, 0), item["points"])
    return min(100, sum(best_by_rule.values()))


def _risk_level(score: int) -> str:
    """Return Low / Medium / High risk category for a given score."""
    if score >= SCORE_HIGH_THRESHOLD:
        return "High"
    if score >= SCORE_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def _summary(score: int, findings: List[Dict[str, Any]]) -> str:
    """
    Build a short plain-text summary.

    Explicitly states that zero matches do not prove safety.
    """
    if not findings:
        return (
            "No indicators matched the current rules. This is not proof that the "
            "content is safe; the rules may miss sophisticated or novel phishing attempts."
        )
    titles = ", ".join(x["title"].lower() for x in findings[:3])
    return (
        f"{len(findings)} indicator(s) matched. "
        f"Main observations: {titles}. "
        "Review the evidence before deciding what to do."
    )


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def extract_urls(text: str) -> List[str]:
    """
    Extract URL-like strings from free text.

    Returns a deduplicated list.  No network requests are made.
    Adds an implicit http:// scheme to bare www. references.
    """
    if not isinstance(text, str):
        return []
    urls: List[str] = []
    for match in LINK_PATTERN.findall(text):
        # Strip common trailing punctuation that is unlikely to be part of the URL.
        candidate = match.rstrip(".,);]}>\"'")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        if candidate not in urls:
            urls.append(candidate)
    return urls


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyze URL structure locally using stdlib urlparse.

    The submitted URL is never visited, downloaded, or resolved via DNS.

    Parameters
    ----------
    url : str
        A URL string.  A bare 'www.' prefix is allowed; http:// will be
        prepended automatically.

    Returns
    -------
    dict with keys: input_type, submitted_input, normalized_url, hostname,
    risk_score, risk_level, findings, summary, timestamp_utc,
    analysis_mode, limitations.

    Raises
    ------
    ValueError
        When the input is empty, not a string, or exceeds MAX_URL_LENGTH.
    """
    if not isinstance(url, str):
        raise ValueError("url must be a string.")
    stripped = url.strip()
    if not stripped:
        raise ValueError("Please provide a non-empty URL.")
    if len(stripped) > MAX_URL_LENGTH:
        raise ValueError(
            f"URL is too long (maximum {MAX_URL_LENGTH} characters)."
        )

    # Normalise: add a scheme if one is absent so urlparse can split the host.
    raw = stripped
    candidate = raw if "://" in raw else "http://" + raw
    parsed = urlparse(candidate)
    findings: List[Dict[str, Any]] = []

    # --- Rule URL001: unusual scheme ---
    if parsed.scheme not in ("http", "https"):
        findings.append(
            _finding(
                "URL001",
                "Unusual URL scheme",
                "medium",
                parsed.scheme or "(missing)",
                "The URL uses a scheme outside the expected HTTP/HTTPS web schemes.",
                "Do not open the link unless you can verify its purpose.",
                20,
            )
        )

    # --- Hostname extraction ---
    host = (parsed.hostname or "").lower().rstrip(".")

    if not host:
        findings.append(
            _finding(
                "URL002",
                "Hostname could not be parsed",
                "high",
                raw,
                "The URL did not contain a recognizable hostname.",
                "Treat the link as suspicious and verify it independently.",
                35,
            )
        )
    else:
        # --- Rule URL003: IP address host ---
        try:
            ipaddress.ip_address(host)
            findings.append(
                _finding(
                    "URL003",
                    "IP address used as hostname",
                    "medium",
                    host,
                    (
                        "The URL uses a literal IP address instead of a conventional "
                        "domain name. This can be legitimate, but warrants review."
                    ),
                    "Verify the destination through a trusted source before proceeding.",
                    15,
                )
            )
        except ValueError:
            pass

        # --- Rule URL004: punycode / IDN hostname ---
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(
                _finding(
                    "URL004",
                    "Internationalized/punycode hostname",
                    "medium",
                    host,
                    (
                        "Punycode may be used legitimately, but can also represent "
                        "visually deceptive domain names."
                    ),
                    "Check the exact domain spelling and the organisation's official domain.",
                    20,
                )
            )

        # --- Rule URL005: many hostname labels ---
        if host.count(".") >= 4:
            findings.append(
                _finding(
                    "URL005",
                    "Many hostname labels",
                    "low",
                    host,
                    (
                        "The hostname contains many dot-separated labels. This is not "
                        "proof of maliciousness, but can obscure the meaningful domain."
                    ),
                    "Read the hostname from right to left and verify the registrable domain.",
                    10,
                )
            )

        # --- Rule URL006: userinfo in URL ---
        if parsed.username is not None or parsed.password is not None:
            findings.append(
                _finding(
                    "URL006",
                    "User information embedded in URL",
                    "high",
                    parsed.netloc,
                    (
                        "The URL includes user-info before the hostname, a pattern "
                        "that can make the actual destination harder to notice."
                    ),
                    "Do not open the link; inspect the actual hostname carefully.",
                    30,
                )
            )

        # --- Rule URL007: security-themed hostname wording ---
        security_words = ("login", "verify", "secure", "account", "update")
        if host.startswith("www-") or any(w in host for w in security_words):
            findings.append(
                _finding(
                    "URL007",
                    "Security-themed hostname wording",
                    "low",
                    host,
                    (
                        "The hostname contains terms often used in account or "
                        "verification messages. These words are not conclusive "
                        "evidence by themselves."
                    ),
                    "Confirm that the domain exactly matches the service's official domain.",
                    8,
                )
            )

    # --- Rule URL008: HTTP (not HTTPS) ---
    # Only flag when the scheme is explicitly http (not when we added http://).
    if raw.lower().startswith("http://"):
        findings.append(
            _finding(
                "URL008",
                "Connection does not use HTTPS",
                "low",
                raw,
                "The URL uses HTTP rather than HTTPS. This alone does not prove phishing.",
                "Avoid entering sensitive information on a page reached through an untrusted link.",
                8,
            )
        )

    # --- Rule URL009: repeated percent-encoding ---
    raw_path = parsed.path or ""
    if re.search(r"(?i)(%[0-9a-f]{2}){3,}", raw_path):
        findings.append(
            _finding(
                "URL009",
                "Repeated URL encoding",
                "low",
                raw_path,
                "The path contains repeated percent-encoded sequences that can make it harder to inspect.",
                "Verify the destination independently and avoid entering credentials.",
                8,
            )
        )

    score = _score_findings(findings)
    return {
        "input_type": "url",
        "submitted_input": raw,
        "normalized_url": candidate,
        "hostname": host or None,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "findings": findings,
        "summary": _summary(score, findings),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_mode": "local_rule_based",
        "limitations": [
            "The URL was not visited.",
            "No live reputation lookup was performed.",
            "A low score does not prove that the URL is safe.",
        ],
    }


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------


def analyze_message(
    message: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze email/SMS text using local rules only.

    Embedded URLs are extracted and individually assessed.  At most 5 URLs
    are analysed per message to limit processing time.

    Parameters
    ----------
    message : str
        The message body text.
    sender : str, optional
        Sender address or phone number.  Used for context checks only.
    subject : str, optional
        Subject line.  Stored in the output; not currently analysed.

    Returns
    -------
    dict with keys: input_type, subject, sender, risk_score, risk_level,
    findings, summary, extracted_urls, timestamp_utc, analysis_mode,
    limitations.

    Note: The full message text is *not* included in the returned dict to
    reduce accidental exposure in exported reports.  Callers that need it
    can retain the original string themselves.

    Raises
    ------
    ValueError
        When the input is not a non-empty string or exceeds MAX_MESSAGE_LENGTH.
    """
    if not isinstance(message, str):
        raise ValueError("message must be a string.")
    if not message.strip():
        raise ValueError("Please provide message text.")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Message is too long (maximum {MAX_MESSAGE_LENGTH:,} characters)."
        )

    findings: List[Dict[str, Any]] = []
    lowered = message.lower()

    # --- Rule MSG001: urgency / pressure language ---
    urgent_hits = [term for term in URGENT_TERMS if term in lowered]
    if urgent_hits:
        findings.append(
            _finding(
                "MSG001",
                "Urgency or pressure language",
                "medium",
                ", ".join(urgent_hits),
                (
                    "The message pressures the recipient to act quickly. "
                    "Urgency can appear in legitimate messages too, so consider "
                    "it alongside other evidence."
                ),
                "Pause and verify the request using an official channel you locate independently.",
                12,
            )
        )

    # --- Rule MSG002: credential / verification request ---
    credential_hits = [term for term in CREDENTIAL_TERMS if term in lowered]
    if credential_hits:
        findings.append(
            _finding(
                "MSG002",
                "Credential or verification request",
                "high",
                ", ".join(credential_hits),
                (
                    "The message mentions passwords, one-time codes, or credentials. "
                    "Unsolicited requests for these details are a significant warning sign."
                ),
                (
                    "Never share passwords or one-time codes through a message link. "
                    "Visit the official service directly if needed."
                ),
                25,
            )
        )

    # --- Rule MSG003: payment / financial language ---
    payment_hits = [term for term in PAYMENT_TERMS if term in lowered]
    if payment_hits:
        findings.append(
            _finding(
                "MSG003",
                "Payment or financial information language",
                "medium",
                ", ".join(payment_hits),
                (
                    "The message asks for payment or references sensitive financial "
                    "details. This can be legitimate, but unexpected requests need "
                    "verification."
                ),
                "Confirm the request with the organisation using a known official contact method.",
                15,
            )
        )

    # --- Rule MSG004: embedded links ---
    urls = extract_urls(message)
    if urls:
        findings.append(
            _finding(
                "MSG004",
                "Link present in message",
                "low",
                ", ".join(urls[:3]),
                (
                    "The message contains one or more links. Links are common in "
                    "legitimate messages too; inspect their destinations before using them."
                ),
                "Do not click unexpected links. Navigate to the official site independently.",
                5,
            )
        )
        for url in urls[:5]:
            try:
                url_result = analyze_url(url)
                for url_finding in url_result["findings"]:
                    # Prefix rule IDs so the source of evidence is clear.
                    copied = dict(url_finding)
                    copied["rule_id"] = "EMBEDDED_" + copied["rule_id"]
                    copied["evidence"] = f"{url} — {copied['evidence']}"
                    findings.append(copied)
            except ValueError:
                # Malformed URL embedded in message — skip gracefully.
                continue

    # --- Rule MSG005: public email provider for organisational claim ---
    sender_text = (sender or "").strip()
    if sender_text and "@" in sender_text:
        sender_domain = sender_text.rsplit("@", 1)[-1].lower()
        consumer_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}
        brand_keywords = (
            "bank", "university", "college", "delivery",
            "microsoft", "google", "paypal",
        )
        if sender_domain in consumer_domains and any(
            brand in lowered for brand in brand_keywords
        ):
            findings.append(
                _finding(
                    "MSG005",
                    "Public email provider used for an organisation claim",
                    "low",
                    sender_text,
                    (
                        "The sender uses a public email provider while the message "
                        "appears to represent an organisation. This can happen "
                        "legitimately, but should be checked."
                    ),
                    "Confirm the sender using the organisation's official website or contact details.",
                    10,
                )
            )

    score = _score_findings(findings)
    return {
        "input_type": "email_or_sms",
        "subject": (subject or "")[:200],
        "sender": sender_text[:320] if sender_text else "",
        "risk_score": score,
        "risk_level": _risk_level(score),
        "findings": findings,
        "summary": _summary(score, findings),
        "extracted_urls": urls,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_mode": "local_rule_based",
        "limitations": [
            "No external reputation lookup was performed.",
            "Message wording alone cannot establish sender identity.",
            "A low score does not prove that the message is safe.",
        ],
    }


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------


def print_report(result: Dict[str, Any]) -> None:
    """Print a readable investigation report to stdout."""
    print("=" * 68)
    print("PHISHGUARD AI 2.0 — INVESTIGATION REPORT")
    print("=" * 68)
    print(f"Type    : {result['input_type']}")
    print(f"Risk    : {result['risk_level']} ({result['risk_score']}/100)")
    print(f"Time UTC: {result['timestamp_utc']}")
    print(f"Summary : {result['summary']}")
    print("\nFindings:")
    if not result["findings"]:
        print("  (No indicators matched the current rules.)")
    for item in result["findings"]:
        print(f"\n  [{item['severity'].upper()}] {item['title']}  (rule {item['rule_id']}, +{item['points']} pts)")
        print(f"  Evidence        : {item['evidence']}")
        print(f"  Why it matters  : {item['explanation']}")
        print(f"  Recommended action: {item['recommendation']}")
    print("\nLimitations:")
    for limitation in result["limitations"]:
        print(f"  - {limitation}")
    print("=" * 68)


# ---------------------------------------------------------------------------
# JSON export helper
# ---------------------------------------------------------------------------


def export_report(result: Dict[str, Any], path: str) -> None:
    """
    Write a result dict to a UTF-8 JSON file.

    Parameters
    ----------
    result : dict
        Return value of analyze_message() or analyze_url().
    path : str
        Destination file path.
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
