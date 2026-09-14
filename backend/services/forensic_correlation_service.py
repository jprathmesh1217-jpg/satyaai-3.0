"""
SatyaAI 3.0 — Forensic Correlation Service
Builds unified threat relationships across multi-vector artifacts:
Email/Call -> URL -> Domain -> Resolved IP -> ASN / ISP -> Infrastructure Location.
"""

import socket
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

from backend.services.forensic_service import (
    extract_all_iocs,
    is_public_ip,
    lookup_abuseipdb,
    lookup_public_ip_geolocation,
)


def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Resolve a domain name to an IPv4 address with short timeout."""
    if not domain:
        return None
    try:
        orig = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            return socket.gethostbyname(domain)
        finally:
            socket.setdefaulttimeout(orig)
    except Exception:
        return None


def correlate_forensics(
    *,
    text: str = "",
    urls: Optional[List[str]] = None,
    header_ips: Optional[List[str]] = None,
    sender_domain: Optional[str] = None,
    source_label: str = "Artifact",
) -> Dict[str, Any]:
    """
    Correlate IOCs into a structured relationship graph and list of threat intelligence items.
    """
    raw_iocs = extract_all_iocs(text)
    combined_urls = list(dict.fromkeys((urls or []) + raw_iocs.get("urls", [])))
    combined_ips = list(dict.fromkeys((header_ips or []) + raw_iocs.get("all_ips", [])))

    ioc_list: List[Dict[str, Any]] = []
    chains: List[Dict[str, Any]] = []
    seen_values = set()

    # 1. Correlate URLs
    for url_item in combined_urls:
        try:
            parsed = urlparse(url_item if "://" in url_item else "http://" + url_item)
            host = parsed.netloc.split(":")[0].lower()
        except Exception:
            host = ""

        resolved_ip = resolve_domain_to_ip(host) if host else None
        geo_data = lookup_public_ip_geolocation(resolved_ip) if resolved_ip else None
        abuse_data = lookup_abuseipdb(resolved_ip) if (resolved_ip and is_public_ip(resolved_ip)) else None

        chain = {
            "source": source_label,
            "url": url_item,
            "host": host,
            "resolved_ip": resolved_ip,
            "is_public_ip": is_public_ip(resolved_ip) if resolved_ip else False,
            "asn": geo_data.get("asn") if geo_data else "N/A",
            "isp": geo_data.get("isp") if geo_data else "Unknown",
            "country": geo_data.get("country") if geo_data else "Unknown",
            "abuse_score": abuse_data.get("abuse_confidence", 0) if abuse_data else 0,
        }
        chains.append(chain)

        if url_item not in seen_values:
            seen_values.add(url_item)
            ioc_list.append({
                "type": "URL",
                "value": url_item,
                "source": source_label,
                "status": "extracted",
                "intelligence": {
                    "host": host,
                    "resolved_ip": resolved_ip,
                    "country": geo_data.get("country") if geo_data else "Unknown",
                    "isp": geo_data.get("isp") if geo_data else "Unknown",
                },
            })

    # 2. Correlate IPs
    for ip_val in combined_ips:
        if ip_val not in seen_values:
            seen_values.add(ip_val)
            pub = is_public_ip(ip_val)
            geo = lookup_public_ip_geolocation(ip_val) if pub else None
            abuse = lookup_abuseipdb(ip_val) if pub else None

            ioc_list.append({
                "type": "IP",
                "value": ip_val,
                "source": "Headers / Content",
                "status": "public" if pub else "private_rfc1918",
                "intelligence": {
                    "is_public": pub,
                    "country": geo.get("country", "Local / Private Network") if geo else "Local / Private Network",
                    "isp": geo.get("isp", "Local Network") if geo else "Local Network",
                    "asn": geo.get("asn", "N/A") if geo else "N/A",
                    "latitude": geo.get("latitude") if geo else None,
                    "longitude": geo.get("longitude") if geo else None,
                    "abuse_confidence_score": abuse.get("abuse_confidence", 0) if abuse else 0,
                    "total_abuse_reports": abuse.get("total_reports", 0) if abuse else 0,
                },
            })

    # 3. Sender domain
    if sender_domain and sender_domain not in seen_values:
        seen_values.add(sender_domain)
        s_ip = resolve_domain_to_ip(sender_domain)
        s_geo = lookup_public_ip_geolocation(s_ip) if s_ip else None
        ioc_list.append({
            "type": "DOMAIN",
            "value": sender_domain,
            "source": "Sender Identity",
            "status": "active_mail_domain",
            "intelligence": {
                "resolved_ip": s_ip,
                "country": s_geo.get("country", "Unknown") if s_geo else "Unknown",
                "isp": s_geo.get("isp", "Unknown") if s_geo else "Unknown",
            },
        })

    return {
        "ioc_count": len(ioc_list),
        "iocs": ioc_list,
        "correlation_chains": chains,
        "extracted_summary": {
            "urls_found": len(combined_urls),
            "ips_found": len(combined_ips),
            "public_ips": sum(1 for ip in combined_ips if is_public_ip(ip)),
            "private_ips": sum(1 for ip in combined_ips if not is_public_ip(ip)),
        },
    }
