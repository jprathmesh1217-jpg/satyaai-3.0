"""
SatyaAI 3.0 — Threat Geolocation & Infrastructure Intelligence Service
=======================================================================
Primary:  IPinfo API  (IPINFO_TOKEN env var)
Fallback: ip-api.com  (free, no key required)
Reputation: AbuseIPDB (ABUSEIPDB_API_KEY env var) — optional, non-blocking

Guarantees:
  - API keys are NEVER exposed to the frontend.
  - Private / RFC-1918 / loopback IPs are NEVER sent to external APIs.
  - AbuseIPDB 401/403/rate-limit errors are caught silently.
  - All lookups are in-memory cached (thread-safe).
  - Zero-crash: any exception falls back gracefully.
  - Locations are clearly marked as APPROXIMATE IP-BASED GEOLOCATION.
"""

import os
import re
import json
import socket
import ipaddress
import threading
import urllib.request
import urllib.error
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("satyaai.geolocation")

# ── Load env vars (dotenv if available) ──────────────────────────────────────

def _load_env():
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=env_path, override=False)
        except ImportError:
            # Manual parse fallback
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        os.environ.setdefault(k.strip(), v.strip())

_load_env()

# ── Thread-safe in-memory caches ─────────────────────────────────────────────

_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_ABUSE_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
_LOCK = threading.Lock()

# Regex: valid IPv4
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


# ── IP validation ─────────────────────────────────────────────────────────────

def is_public_ip(ip_str: Optional[str]) -> bool:
    """
    Returns True only for globally routable public IPv4/IPv6 addresses.
    Rejects: private (RFC 1918), loopback, link-local, multicast, reserved, CGN.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        obj = ipaddress.ip_address(ip_str.strip())
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except ValueError:
        return False


def clean_host_string(host_or_url: str) -> str:
    """Strip scheme, port, path — return bare hostname or IP."""
    if not host_or_url:
        return ""
    host = host_or_url.strip()
    if "://" in host:
        try:
            parsed = urlparse(host)
            host = parsed.hostname or parsed.netloc or parsed.path
        except Exception:
            pass
    elif "/" in host:
        host = host.split("/")[0]
    # Remove port
    if host and ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    return host.strip().lower()


# ── DNS resolution ────────────────────────────────────────────────────────────

def resolve_domain_ips(domain_or_host: str, max_ips: int = 3) -> List[str]:
    """
    Resolve a domain/hostname to public IPv4 addresses (2 s timeout).
    If the input is already a public IP, return it directly.
    Private/reserved IPs are silently dropped.
    """
    host = clean_host_string(domain_or_host)
    if not host:
        return []

    # Already a public IP?
    if is_public_ip(host):
        return [host]

    # Already a private IP — skip entirely
    if IPV4_REGEX.match(host):
        return []

    results: List[str] = []
    orig = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        for item in addr_info:
            ip = item[4][0]
            if is_public_ip(ip) and ip not in results:
                results.append(ip)
                if len(results) >= max_ips:
                    break
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(orig)
    return results


# ── IPinfo primary geolocation ────────────────────────────────────────────────

def _geolocate_via_ipinfo(ip: str, token: str) -> Optional[Dict[str, Any]]:
    """Query IPinfo API. Returns normalized dict or None on any error."""
    try:
        url = f"https://ipinfo.io/{ip}/json?token={token}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SatyaAI-ThreatIntel/3.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("bogon") or not data.get("ip"):
            return None

        loc = data.get("loc", "0,0").split(",")
        try:
            lat = float(loc[0])
            lon = float(loc[1])
        except (ValueError, IndexError):
            lat, lon = 0.0, 0.0

        org_raw = data.get("org", "")           # e.g. "AS13335 Cloudflare, Inc."
        asn = ""
        org_name = org_raw
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else org_raw

        return {
            "ip": ip,
            "hostname": data.get("hostname", ""),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),   # 2-letter code from IPinfo
            "country_name": data.get("country", "Unknown"),
            "country_code": data.get("country", "UNK"),
            "latitude": lat,
            "longitude": lon,
            "organization": org_name,
            "isp": org_name,
            "asn": asn,
            "timezone": data.get("timezone", ""),
            "network": data.get("network", ""),
            "source": "IPinfo",
        }
    except Exception as exc:
        logger.debug(f"IPinfo lookup failed for {ip}: {exc}")
        return None


# ── ip-api.com fallback geolocation ──────────────────────────────────────────

def _geolocate_via_ipapi(ip: str) -> Optional[Dict[str, Any]]:
    """Query ip-api.com (free, no key). Returns normalized dict or None."""
    try:
        fields = "status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SatyaAI-ThreatIntel/3.0"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("status") != "success":
            return None

        asn_raw = data.get("as", "")
        asn = asn_raw.split(" ")[0] if asn_raw else ""

        return {
            "ip": ip,
            "hostname": "",
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "country": data.get("country", "Unknown"),
            "country_name": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", "UNK"),
            "latitude": float(data.get("lat", 0.0)),
            "longitude": float(data.get("lon", 0.0)),
            "organization": data.get("org", "") or data.get("isp", "Unknown"),
            "isp": data.get("isp", "Unknown ISP"),
            "asn": asn,
            "timezone": "",
            "network": "",
            "source": "ip-api.com",
        }
    except Exception as exc:
        logger.debug(f"ip-api.com lookup failed for {ip}: {exc}")
        return None


# ── AbuseIPDB reputation (optional, non-blocking) ────────────────────────────

def get_abuse_intel(ip: str) -> Optional[Dict[str, Any]]:
    """
    Query AbuseIPDB for IP reputation. Returns dict or None.
    Silently swallows 401, 403, 429, and any network error.
    Result is cached per IP. Token read from ABUSEIPDB_API_KEY env var.
    NEVER exposes the key to the frontend.
    """
    if not is_public_ip(ip):
        return None

    with _LOCK:
        if ip in _ABUSE_CACHE:
            return _ABUSE_CACHE[ip]

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        with _LOCK:
            _ABUSE_CACHE[ip] = None
        return None

    result: Optional[Dict[str, Any]] = None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(
            url,
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "SatyaAI-ThreatIntel/3.0",
            },
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8")).get("data", {})

        result = {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "country_code": data.get("countryCode", ""),
            "source": "AbuseIPDB",
        }
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 429):
            logger.warning(f"AbuseIPDB key issue (HTTP {e.code}) for {ip} — skipping reputation check.")
        else:
            logger.debug(f"AbuseIPDB HTTP error {e.code} for {ip}")
    except Exception as exc:
        logger.debug(f"AbuseIPDB lookup failed for {ip}: {exc}")

    with _LOCK:
        _ABUSE_CACHE[ip] = result
    return result


# ── Unified geolocation entry point ──────────────────────────────────────────

def geolocate_ip(ip: str, include_abuse: bool = True) -> Optional[Dict[str, Any]]:
    """
    Full IP intelligence lookup.
    1. Cache check
    2. IPinfo (if IPINFO_TOKEN set)
    3. ip-api.com fallback
    4. AbuseIPDB reputation merge (if ABUSEIPDB_API_KEY set)

    Returns enriched dict or None if not a public IP.
    Locations are APPROXIMATE IP-BASED GEOLOCATION.
    """
    if not is_public_ip(ip):
        return None

    clean = ip.strip()

    with _LOCK:
        if clean in _GEO_CACHE:
            cached = dict(_GEO_CACHE[clean])
            # Re-attach live abuse data (may have been populated later)
            if include_abuse and "abuse" not in cached:
                abuse = get_abuse_intel(clean)
                if abuse:
                    cached["abuse"] = abuse
            return cached

    # 1. IPinfo (primary)
    geo: Optional[Dict[str, Any]] = None
    token = os.getenv("IPINFO_TOKEN", "").strip()
    if token:
        geo = _geolocate_via_ipinfo(clean, token)

    # 2. ip-api.com (fallback)
    if not geo:
        geo = _geolocate_via_ipapi(clean)

    if not geo:
        return None

    # Ensure coords are real numbers
    try:
        geo["latitude"] = float(geo.get("latitude") or 0.0)
        geo["longitude"] = float(geo.get("longitude") or 0.0)
    except (TypeError, ValueError):
        geo["latitude"] = 0.0
        geo["longitude"] = 0.0

    # 3. AbuseIPDB reputation (non-blocking, optional)
    if include_abuse:
        abuse = get_abuse_intel(clean)
        geo["abuse"] = abuse  # None if unavailable

    with _LOCK:
        _GEO_CACHE[clean] = dict(geo)

    return geo


# ── High-level domain→geo convenience ────────────────────────────────────────

def geolocate_domain(domain_or_url: str, include_abuse: bool = True) -> Optional[Dict[str, Any]]:
    """
    Resolve domain/URL to its first public IP then geolocate it.
    Returns None if domain cannot be resolved or IP is private.
    """
    host = clean_host_string(domain_or_url)
    if not host:
        return None
    ips = resolve_domain_ips(host, max_ips=1)
    if not ips:
        return None
    return geolocate_ip(ips[0], include_abuse=include_abuse)


# ── Marker builder (used by url_service + email_service) ─────────────────────

def build_threat_origin_markers(
    infrastructure_items: List[Dict[str, Any]],
    default_threat_type: str = "Suspicious Infrastructure",
    default_risk_score: int = 50,
    source: str = "Threat Analysis",
) -> Dict[str, Any]:
    """
    Process candidate infrastructure items (domains/IPs) into a deduplicated,
    standardized `threat_origin` payload for the Live Threat Origin Map.

    Each input item may have: type, label, domain, host, ip, risk_score,
    threat_type, source.

    Returns:
        {
            "status": "success" | "unavailable",
            "markers": [...],       ← safe to render in frontend
            "disclaimer": "...",
        }
    """
    markers: List[Dict[str, Any]] = []
    seen_ips: set = set()

    for item in infrastructure_items:
        item_type = item.get("type", "domain")
        label = (
            item.get("label")
            or item.get("domain")
            or item.get("host")
            or item.get("ip")
            or "Infrastructure"
        )
        raw_ip = item.get("ip")
        domain = item.get("domain") or item.get("host")
        risk_score = int(item.get("risk_score", default_risk_score))
        threat_type = item.get("threat_type", default_threat_type)
        item_source = item.get("source", source)

        ips_to_query: List[str] = []
        if raw_ip and is_public_ip(raw_ip):
            ips_to_query.append(raw_ip.strip())
        elif domain:
            resolved = resolve_domain_ips(domain, max_ips=2)
            ips_to_query.extend(resolved)

        for ip in ips_to_query:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            geo = geolocate_ip(ip, include_abuse=True)
            if not geo:
                continue

            lat = geo.get("latitude", 0.0)
            lon = geo.get("longitude", 0.0)
            if lat == 0.0 and lon == 0.0:
                continue    # Skip un-geolocatable IPs silently

            # Build safe marker — NEVER include API keys
            marker: Dict[str, Any] = {
                "type": item_type,
                "label": label,
                "ip": ip,
                "hostname": geo.get("hostname", ""),
                "country": geo.get("country_name") or geo.get("country", "Unknown"),
                "country_code": geo.get("country_code", "UNK"),
                "region": geo.get("region", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "latitude": float(lat),
                "longitude": float(lon),
                "isp": geo.get("isp", "Unknown ISP"),
                "organization": geo.get("organization", "Unknown Organization"),
                "asn": geo.get("asn", ""),
                "timezone": geo.get("timezone", ""),
                "network": geo.get("network", ""),
                "geo_source": geo.get("source", "Unknown"),
                "risk_score": risk_score,
                "threat_type": threat_type,
                "source": item_source,
            }

            # Attach abuse intel if available (safe subset — no keys)
            abuse = geo.get("abuse")
            if abuse:
                marker["abuse"] = {
                    "confidence_score": abuse.get("abuse_confidence_score", 0),
                    "total_reports": abuse.get("total_reports", 0),
                    "usage_type": abuse.get("usage_type", ""),
                    "domain": abuse.get("domain", ""),
                    "last_reported_at": abuse.get("last_reported_at"),
                    "is_whitelisted": abuse.get("is_whitelisted", False),
                }
            else:
                marker["abuse"] = None

            markers.append(marker)

    if markers:
        return {
            "status": "success",
            "markers": markers,
            "disclaimer": (
                "⚠️ APPROXIMATE IP-BASED GEOLOCATION — "
                "Locations represent analyzed network infrastructure, "
                "not necessarily the attacker's physical location."
            ),
        }
    return {
        "status": "unavailable",
        "markers": [],
        "message": "Geolocation unavailable for this infrastructure.",
    }


# ── Standalone IP intelligence endpoint helper ────────────────────────────────

def full_ip_intel(target: str) -> Dict[str, Any]:
    """
    Full IP/domain intelligence report for the /api/ip-intel endpoint.
    Accepts: raw IP, domain, or URL.
    Returns complete geo + abuse intel or structured error dict.
    """
    host = clean_host_string(target)
    if not host:
        return {"error": "No valid host or IP provided.", "target": target}

    # Resolve domain → IP if needed
    if is_public_ip(host):
        ip = host
    else:
        ips = resolve_domain_ips(host, max_ips=1)
        if not ips:
            return {
                "error": f"Could not resolve '{host}' to a public IP address.",
                "target": target,
                "host": host,
                "resolved_ip": None,
            }
        ip = ips[0]

    geo = geolocate_ip(ip, include_abuse=True)
    if not geo:
        return {
            "error": f"Geolocation unavailable for {ip}.",
            "target": target,
            "host": host,
            "resolved_ip": ip,
        }

    abuse = geo.pop("abuse", None)

    return {
        "target": target,
        "host": host,
        "resolved_ip": ip,
        "geolocation": {
            **geo,
            "disclaimer": (
                "APPROXIMATE IP-BASED GEOLOCATION — "
                "This represents network infrastructure location, "
                "not an attacker's physical address."
            ),
        },
        "abuse_intel": {
            k: v for k, v in abuse.items()
            if k not in ("source",)   # safe subset
        } if abuse else None,
        "threat_origin": build_threat_origin_markers(
            [{"type": "query", "label": host, "ip": ip,
              "risk_score": 50, "threat_type": "IP Intelligence Query",
              "source": "Direct Lookup"}],
            source="Direct IP Intel",
        ),
    }
