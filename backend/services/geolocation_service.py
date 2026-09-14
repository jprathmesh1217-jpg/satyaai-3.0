"""
SatyaAI 3.0 — Threat Origin & Geolocation Intelligence Service
Extracts, validates, resolves, and geolocates public infrastructure (hosts, mail servers, domain IPs).
Guarantees resilient fallback and zero impact on core ML threat classification.
"""

import os
import re
import socket
import json
import ipaddress
import threading
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Thread-safe in-memory cache for IP geolocations
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_GEO_LOCK = threading.Lock()

# Regex patterns for validation
IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def is_public_ip(ip_str: Optional[str]) -> bool:
    """
    Strictly validates whether an IP address is a routable public internet address.
    Rejects:
      - Private RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Loopback (127.0.0.0/8, ::1)
      - Link-local (169.254.0.0/16, fe80::/10)
      - Multicast (224.0.0.0/4, ff00::/8)
      - Reserved / Carrier-grade NAT / Unspecified (0.0.0.0/8, 100.64.0.0/10, etc.)
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def clean_host_string(host_or_url: str) -> str:
    """Extract clean domain/hostname without scheme, port, or path."""
    if not host_or_url:
        return ""
    host = host_or_url.strip()
    if "://" in host:
        try:
            parsed = urlparse(host)
            host = parsed.netloc or parsed.path
        except Exception:
            pass
    elif "/" in host:
        host = host.split("/")[0]
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return host.strip().lower()


def resolve_domain_ips(domain_or_host: str, max_ips: int = 3) -> List[str]:
    """
    Safely resolve a domain or hostname to its public IPv4 addresses with a 2.0s timeout.
    Returns list of unique public IPv4 addresses.
    """
    clean_host = clean_host_string(domain_or_host)
    if not clean_host:
        return []

    # If it's already an IP address
    if is_public_ip(clean_host):
        return [clean_host]
    elif IPV4_REGEX.match(clean_host):
        # It's a private or reserved IP
        return []

    resolved_public_ips: List[str] = []
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_INET, socket.SOCK_STREAM)
            for item in addr_info:
                ip_cand = item[4][0]
                if is_public_ip(ip_cand) and ip_cand not in resolved_public_ips:
                    resolved_public_ips.append(ip_cand)
                    if len(resolved_public_ips) >= max_ips:
                        break
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        pass

    return resolved_public_ips


def geolocate_ip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Perform approximate IP geolocation lookup with caching and safe error handling.
    Uses free public ip-api.com endpoint with User-Agent header, or IPinfo if configured.
    Timeout: 2.5 seconds.
    """
    if not is_public_ip(ip):
        return None

    clean_ip = ip.strip()

    with _GEO_LOCK:
        if clean_ip in _GEO_CACHE:
            return dict(_GEO_CACHE[clean_ip])

    # Check for optional API keys or tokens in environment
    ipinfo_token = os.getenv("IPINFO_TOKEN") or os.getenv("GEOLOCATION_API_KEY")
    result: Optional[Dict[str, Any]] = None

    if ipinfo_token:
        # IPinfo API integration
        try:
            url = f"https://ipinfo.io/{clean_ip}/json?token={ipinfo_token}"
            req = urllib.request.Request(url, headers={"User-Agent": "SatyaAI-ThreatOrigin/3.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                loc = data.get("loc", "").split(",")
                lat = float(loc[0]) if len(loc) == 2 else 0.0
                lon = float(loc[1]) if len(loc) == 2 else 0.0
                result = {
                    "ip": clean_ip,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("country", "UNK"),
                    "region": data.get("region", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": lat,
                    "longitude": lon,
                    "isp": data.get("org", "Unknown ISP"),
                    "organization": data.get("org", "Unknown Organization"),
                    "asn": data.get("org", "").split(" ")[0] if "AS" in data.get("org", "") else "N/A",
                }
        except Exception:
            result = None

    if not result:
        # Standard free, high-speed ip-api.com lookup
        try:
            api_url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"
            req = urllib.request.Request(api_url, headers={"User-Agent": "SatyaAI-ThreatOrigin/3.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success":
                lat = float(data.get("lat")) if data.get("lat") is not None else 0.0
                lon = float(data.get("lon")) if data.get("lon") is not None else 0.0
                result = {
                    "ip": clean_ip,
                    "country": data.get("country") or "Unknown",
                    "country_code": data.get("countryCode") or "UNK",
                    "region": data.get("regionName") or "Unknown",
                    "city": data.get("city") or "Unknown",
                    "latitude": lat,
                    "longitude": lon,
                    "isp": data.get("isp") or "Unknown ISP",
                    "organization": data.get("org") or data.get("isp") or "Unknown Organization",
                    "asn": data.get("as") or "N/A",
                }
        except Exception:
            result = None

    if result:
        with _GEO_LOCK:
            _GEO_CACHE[clean_ip] = dict(result)
        return result

    return None


def build_threat_origin_markers(
    infrastructure_items: List[Dict[str, Any]],
    default_threat_type: str = "Suspicious Infrastructure",
    default_risk_score: int = 50,
    source: str = "Threat Analysis",
) -> Dict[str, Any]:
    """
    Process candidate infrastructure items (domains, hostnames, IPs) into a
    deduplicated, standardized `threat_origin` payload for the Live Threat Origin Map.
    """
    markers: List[Dict[str, Any]] = []
    seen_ips = set()

    for item in infrastructure_items:
        item_type = item.get("type", "domain")  # "domain" | "mail_server" | "originating_ip" | "received_hop" | "url_host"
        label = item.get("label") or item.get("domain") or item.get("host") or item.get("ip") or "Infrastructure"
        raw_ip = item.get("ip")
        domain = item.get("domain") or item.get("host")
        risk_score = item.get("risk_score", default_risk_score)
        threat_type = item.get("threat_type", default_threat_type)
        item_source = item.get("source", source)

        ips_to_query: List[str] = []
        if raw_ip and is_public_ip(raw_ip):
            ips_to_query.append(raw_ip.strip())
        elif domain:
            resolved = resolve_domain_ips(domain)
            ips_to_query.extend(resolved)

        for ip in ips_to_query:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            geo = geolocate_ip(ip)
            if not geo:
                continue

            # Ensure coordinates exist and are valid numbers
            lat = geo.get("latitude")
            lon = geo.get("longitude")
            if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
                continue

            markers.append({
                "type": item_type,
                "label": label,
                "ip": ip,
                "country": geo.get("country", "Unknown"),
                "country_code": geo.get("country_code", "UNK"),
                "region": geo.get("region", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "latitude": float(lat),
                "longitude": float(lon),
                "isp": geo.get("isp", "Unknown ISP"),
                "organization": geo.get("organization", "Unknown Organization"),
                "asn": geo.get("asn", "N/A"),
                "risk_score": int(risk_score),
                "threat_type": threat_type,
                "source": item_source,
            })

    if markers:
        return {
            "status": "success",
            "markers": markers,
            "disclaimer": "Locations are approximate and represent analyzed network infrastructure, not necessarily the attacker's physical location.",
        }
    else:
        return {
            "status": "unavailable",
            "markers": [],
            "message": "Geolocation unavailable for this infrastructure.",
        }
