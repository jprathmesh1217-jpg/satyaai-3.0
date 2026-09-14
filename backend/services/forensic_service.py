"""
SatyaAI 3.0 — Forensic Intelligence Service
Extracts Indicators of Compromise (IOCs) including public IPs, domains, URLs,
email addresses, and cryptographic hashes.
Provides AbuseIPDB reputation lookups and public infrastructure geolocation.
"""

import os
import re
import socket
import json
import urllib.request
import urllib.error
import ipaddress
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Strict IP regex pattern
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
HASH_MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
HASH_SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
URL_PATTERN = r'https?://[^\s<>"\'{}|\\^`]+'

# In-memory IOC cache to prevent duplicate external lookups
_IOC_CACHE: Dict[str, Dict[str, Any]] = {}


def is_public_ip(ip_str: str) -> bool:
    """
    Check if an IPv4/IPv6 string is a valid routable public internet IP address.
    Returns False for private (RFC 1918), loopback, link-local, multicast, or reserved IPs.
    """
    if not ip_str:
        return False
    try:
        obj = ipaddress.ip_address(ip_str.strip())
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_reserved
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_unspecified
        )
    except ValueError:
        return False


def extract_ips(text: str) -> List[str]:
    """Extract valid unique IPv4 addresses from text."""
    if not text:
        return []
    raw = re.findall(IP_PATTERN, text)
    valid: List[str] = []
    for candidate in raw:
        try:
            ipaddress.ip_address(candidate)
            if candidate not in valid:
                valid.append(candidate)
        except ValueError:
            pass
    return valid


def extract_urls(text: str) -> List[str]:
    """Extract and deduplicate URLs from text."""
    if not text:
        return []
    found = re.findall(URL_PATTERN, text)
    return list(dict.fromkeys(found))


def extract_domains(text: str) -> List[str]:
    """Extract and deduplicate domain names from text."""
    if not text:
        return []
    raw = re.findall(DOMAIN_PATTERN, text)
    cleaned = []
    for d in raw:
        d_lower = d.lower().rstrip(".")
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', d_lower):
            if d_lower not in cleaned:
                cleaned.append(d_lower)
    return cleaned


def extract_emails(text: str) -> List[str]:
    """Extract unique email addresses from text."""
    if not text:
        return []
    return list(dict.fromkeys(re.findall(EMAIL_PATTERN, text)))


def extract_hashes(text: str) -> Dict[str, List[str]]:
    """Extract potential MD5 and SHA-256 hashes from text."""
    if not text:
        return {"md5": [], "sha256": []}
    md5s = list(dict.fromkeys(re.findall(HASH_MD5_PATTERN, text)))
    sha256s = list(dict.fromkeys(re.findall(HASH_SHA256_PATTERN, text)))
    return {"md5": md5s, "sha256": sha256s}


def extract_all_iocs(text: str) -> Dict[str, Any]:
    """Extract all categories of IOCs from arbitrary text."""
    all_ips = extract_ips(text)
    public_ips = [ip for ip in all_ips if is_public_ip(ip)]
    private_ips = [ip for ip in all_ips if not is_public_ip(ip)]
    urls = extract_urls(text)
    domains = extract_domains(text)
    emails = extract_emails(text)
    hashes = extract_hashes(text)

    return {
        "all_ips": all_ips,
        "public_ips": public_ips,
        "private_ips": private_ips,
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "hashes": hashes,
    }


def lookup_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB API v2 for IP threat reputation.
    Uses ABUSEIPDB_API_KEY environment variable.
    Gracefully handles missing keys and API limits without failing analysis.
    Never returns API key in output.
    """
    if not is_public_ip(ip):
        return {
            "status": "skipped",
            "message": "AbuseIPDB query skipped: IP is private/local address.",
            "ip": ip,
            "abuse_confidence": 0,
            "total_reports": 0,
        }

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    # Check if key is configured and not default template
    if not api_key or api_key == "PASTE_YOUR_ABUSEIPDB_API_KEY_HERE":
        return {
            "status": "unconfigured",
            "message": "AbuseIPDB API key not configured. Reputation lookup skipped.",
            "ip": ip,
            "abuse_confidence": 0,
            "total_reports": 0,
        }

    cache_key = f"abuseipdb:{ip}"
    if cache_key in _IOC_CACHE:
        return _IOC_CACHE[cache_key]

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Key": api_key,
            "User-Agent": "SatyaAI-ThreatIntel/3.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8")).get("data", {})
            result = {
                "status": "success",
                "ip": data.get("ipAddress", ip),
                "is_whitelisted": data.get("isWhitelisted", False),
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "UNK"),
                "usage_type": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
            }
            _IOC_CACHE[cache_key] = result
            return result
    except Exception as exc:
        return {
            "status": "partial",
            "message": f"AbuseIPDB query failed: {exc}",
            "ip": ip,
            "abuse_confidence": 0,
            "total_reports": 0,
        }


def lookup_public_ip_geolocation(ip: str) -> Dict[str, Any]:
    """
    Retrieve approximate network infrastructure geolocation for public IP addresses.
    Does NOT track physical individuals; identifies autonomous system and host data.
    """
    if not is_public_ip(ip):
        return {
            "status": "private",
            "ip": ip,
            "is_public": False,
            "country": "Local / Private Network",
            "country_code": "LAN",
            "region": "Internal Network (RFC 1918 / Bogon)",
            "city": "Private Subnet",
            "isp": "Local Area Network",
            "org": "Private Infrastructure",
            "asn": "N/A (Private)",
            "latitude": None,
            "longitude": None,
        }

    cache_key = f"geo:{ip}"
    if cache_key in _IOC_CACHE:
        return _IOC_CACHE[cache_key]

    api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "SatyaAI-ThreatIntel/3.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("status") == "success":
            res = {
                "status": "success",
                "ip": ip,
                "is_public": True,
                "country": data.get("country") or "Unknown",
                "country_code": data.get("countryCode") or "UNK",
                "region": data.get("regionName") or "Unknown",
                "city": data.get("city") or "Unknown",
                "isp": data.get("isp") or "Unknown ISP",
                "org": data.get("org") or data.get("isp") or "Unknown Org",
                "asn": data.get("as") or "N/A",
                "latitude": float(data.get("lat")) if data.get("lat") is not None else None,
                "longitude": float(data.get("lon")) if data.get("lon") is not None else None,
            }
        else:
            res = {
                "status": "partial",
                "ip": ip,
                "is_public": True,
                "country": "External Host",
                "country_code": "EXT",
                "region": "Public IP Range",
                "city": "Unknown",
                "isp": "Public Internet Host",
                "org": "Unknown",
                "asn": "N/A",
                "latitude": None,
                "longitude": None,
            }
    except Exception:
        res = {
            "status": "offline",
            "ip": ip,
            "is_public": True,
            "country": "Public Host (Geo Offline)",
            "country_code": "UNK",
            "region": "Resolved IP Online",
            "city": "Unknown",
            "isp": "Public Network",
            "org": "Public Network",
            "asn": "N/A",
            "latitude": None,
            "longitude": None,
        }

    _IOC_CACHE[cache_key] = res
    return res
