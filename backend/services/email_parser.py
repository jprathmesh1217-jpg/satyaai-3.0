"""
SatyaAI 3.0 — Email Parser & Header Forensics Service
Parses .eml and raw RFC 822 email messages using standard BytesParser with policy.default.
Extracts headers, authentication results (SPF, DKIM, DMARC), Received IP hops,
body content, and sender verification signals.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from backend.services.forensic_service import extract_ips, is_public_ip


def _parse_address(addr_str: Optional[str]) -> Dict[str, str]:
    """Parse address header into display name, email, and domain."""
    if not addr_str:
        return {"display_name": "", "email": "", "domain": ""}

    # Pattern: "Name <user@domain.com>" or "user@domain.com"
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', addr_str)
    email_addr = match.group(0).lower() if match else ""
    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""

    display_name = re.sub(r'<[^>]+>', '', addr_str).strip(' "\'')
    return {
        "raw": addr_str,
        "display_name": display_name,
        "email": email_addr,
        "domain": domain,
    }


def parse_eml_bytes(eml_bytes: bytes) -> Dict[str, Any]:
    """Parse raw .eml bytes into structured headers, body, and authentication telemetry."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
    except Exception as exc:
        raise ValueError(f"Corrupted or invalid EML file format: {exc}") from exc

    # 1. Extract important headers
    important_headers = [
        "From", "To", "Subject", "Date", "Reply-To", "Return-Path",
        "Message-ID", "Received", "Authentication-Results",
        "Received-SPF", "DKIM-Signature", "Content-Type",
    ]
    raw_headers: Dict[str, List[str]] = {}
    for h in important_headers:
        values = msg.get_all(h, [])
        raw_headers[h] = [str(v) for v in values]

    from_info = _parse_address(msg.get("From"))
    to_info = _parse_address(msg.get("To"))
    reply_to_info = _parse_address(msg.get("Reply-To"))
    return_path_info = _parse_address(msg.get("Return-Path"))
    subject = str(msg.get("Subject") or "")
    date_str = str(msg.get("Date") or "")
    message_id = str(msg.get("Message-ID") or "")

    # 2. Extract Body (Plain Text & HTML)
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in content_disposition:
                continue

            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    if content_type == "text/plain":
                        body_text += "\n" + payload
                    elif content_type == "text/html":
                        body_html += "\n" + payload
            except Exception:
                pass
    else:
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                if msg.get_content_type() == "text/html":
                    body_html = payload
                else:
                    body_text = payload
        except Exception:
            body_text = str(msg.get_payload() or "")

    # Clean HTML to plain text if plain text is empty
    if not body_text.strip() and body_html.strip():
        # Strip HTML tags
        clean_text = re.sub(r'<[^>]+>', ' ', body_html)
        body_text = re.sub(r'\s+', ' ', clean_text).strip()

    # 3. Extract Received IPs & Originating IP
    received_headers = raw_headers.get("Received", [])
    received_text = " ".join(received_headers)
    all_received_ips = extract_ips(received_text)
    public_received_ips = [ip for ip in all_received_ips if is_public_ip(ip)]

    # Check dedicated originating IP headers
    originating_ip = ""
    for hdr in ["X-Originating-IP", "X-Sender-IP", "X-Real-IP"]:
        raw_val = msg.get(hdr)
        if raw_val:
            found_ips = extract_ips(str(raw_val))
            pub_ips = [ip for ip in found_ips if is_public_ip(ip)]
            if pub_ips:
                originating_ip = pub_ips[0]
                break

    # If no X-Originating-IP, first public hop in received headers is closest to sender
    if not originating_ip and public_received_ips:
        originating_ip = public_received_ips[-1]

    # Extract mail server hostnames from Received: from <host> by <host>
    mail_servers: List[str] = []
    for r_hdr in received_headers:
        matches = re.findall(r'(?:from|by)\s+([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})', r_hdr, re.IGNORECASE)
        for m in matches:
            m_clean = m.lower().strip(".")
            if not is_public_ip(m_clean) and m_clean not in mail_servers and m_clean != "localhost":
                mail_servers.append(m_clean)

    # Extract DKIM signature domain
    dkim_domain = ""
    for dkim_hdr in raw_headers.get("DKIM-Signature", []):
        m_d = re.search(r'\bd=([a-zA-Z0-9.-]+)', dkim_hdr, re.IGNORECASE)
        if m_d:
            dkim_domain = m_d.group(1).lower().strip(".")
            break

    # 4. Authentication Results Evaluation (SPF, DKIM, DMARC)
    auth_results_text = " ".join(raw_headers.get("Authentication-Results", [])).lower()
    spf_header_text = " ".join(raw_headers.get("Received-SPF", [])).lower()

    spf_status = "unknown"
    if "spf=pass" in auth_results_text or "pass" in spf_header_text:
        spf_status = "pass"
    elif "spf=fail" in auth_results_text or "fail" in spf_header_text:
        spf_status = "fail"
    elif "spf=softfail" in auth_results_text or "softfail" in spf_header_text:
        spf_status = "softfail"
    elif "spf=neutral" in auth_results_text or "neutral" in spf_header_text:
        spf_status = "neutral"

    dkim_status = "unknown"
    if "dkim=pass" in auth_results_text or raw_headers.get("DKIM-Signature"):
        dkim_status = "pass" if "dkim=pass" in auth_results_text else "present"
    elif "dkim=fail" in auth_results_text:
        dkim_status = "fail"

    dmarc_status = "unknown"
    if "dmarc=pass" in auth_results_text:
        dmarc_status = "pass"
    elif "dmarc=fail" in auth_results_text:
        dmarc_status = "fail"

    # 5. Header Signals & Mismatches
    header_signals: List[Dict[str, str]] = []

    # From vs Reply-To Mismatch
    if from_info["domain"] and reply_to_info["domain"]:
        if from_info["domain"] != reply_to_info["domain"]:
            header_signals.append({
                "type": "HEADER_MISMATCH",
                "description": f"From domain ({from_info['domain']}) does not match Reply-To domain ({reply_to_info['domain']}). Classic spoofing pattern.",
            })

    # SPF / DKIM / DMARC failures
    if spf_status == "fail":
        header_signals.append({
            "type": "SPF_FAILURE",
            "description": "SPF validation failed: Sender IP is not authorized by the declared domain's SPF record.",
        })
    elif spf_status == "softfail":
        header_signals.append({
            "type": "SPF_SOFTFAIL",
            "description": "SPF softfail: Domain owner discourages this sending IP address.",
        })

    if dkim_status == "fail":
        header_signals.append({
            "type": "DKIM_FAILURE",
            "description": "DKIM cryptographic signature verification failed or was tampered in transit.",
        })

    if dmarc_status == "fail":
        header_signals.append({
            "type": "DMARC_FAILURE",
            "description": "DMARC policy alignment failed.",
        })

    # Suspicious domain lookalike or free-mail brand spoof
    free_mail_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}
    bank_names = ["sbi", "hdfc", "icici", "axis", "paypal", "netflix", "apple", "amazon", "microsoft", "chase"]
    from_name_lower = from_info["display_name"].lower()
    from_domain_lower = from_info["domain"]

    for b in bank_names:
        if b in from_name_lower and from_domain_lower in free_mail_providers:
            header_signals.append({
                "type": "FREE_MAIL_SPOOF",
                "description": f"Corporate/Bank identity '{from_info['display_name']}' sent from free public mail provider ({from_domain_lower}).",
            })
            break

    return {
        "subject": subject,
        "from": from_info,
        "to": to_info,
        "reply_to": reply_to_info,
        "return_path": return_path_info,
        "date": date_str,
        "message_id": message_id,
        "body_text": body_text.strip(),
        "body_html": body_html.strip(),
        "received_ips": {
            "all": all_received_ips,
            "public": public_received_ips,
        },
        "infrastructure": {
            "sender_domain": from_info.get("domain", ""),
            "reply_to_domain": reply_to_info.get("domain", ""),
            "return_path_domain": return_path_info.get("domain", ""),
            "originating_ip": originating_ip,
            "received_ips": public_received_ips,
            "mail_servers": mail_servers[:6],
            "dkim_domain": dkim_domain,
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "raw_auth_results": raw_headers.get("Authentication-Results", []),
        },
        "raw_headers": raw_headers,
        "header_signals": header_signals,
    }
