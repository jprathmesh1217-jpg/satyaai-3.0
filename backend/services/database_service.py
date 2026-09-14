"""
SatyaAI 3.0 — Database Persistence Service
===========================================
Extracts structured telemetry from analysis results and safely persists them
to PostgreSQL via SQLAlchemy. All DB failures are non-blocking.
"""
import uuid
import logging
from typing import Optional, List, Any
from sqlalchemy.orm import Session
from backend.database.models import Analysis

logger = logging.getLogger("satyaai.database_service")


# ── Telemetry extractor ───────────────────────────────────────────────────────

def extract_telemetry_fields(
    analysis_data: dict,
    input_type: str,
    input_data: Optional[str] = None,
) -> dict:
    """
    Normalize an analysis result payload into flat DB fields.
    Handles all modalities: message, url, email, image, audio, video, call.
    """
    risk   = analysis_data.get("risk_assessment") or analysis_data.get("risk") or {}
    inner  = analysis_data.get("analysis") or {}
    final  = analysis_data.get("final_analysis") or {}

    # ── Risk score ──────────────────────────────────────────────────────────
    score = (
        risk.get("final_score")
        if risk.get("final_score") is not None else
        risk.get("score")
        if risk.get("score") is not None else
        analysis_data.get("risk_score")
        if analysis_data.get("risk_score") is not None else
        inner.get("probability")
        if inner.get("probability") is not None else
        inner.get("scam_probability")
    )
    if score is not None:
        try:
            score = int(round(float(score)))
        except (ValueError, TypeError):
            score = None

    # ── Threat level ─────────────────────────────────────────────────────────
    level = (
        risk.get("risk_level")
        or risk.get("level")
        or analysis_data.get("risk_level")
        or (inner.get("ml") or {}).get("prediction_label")
        or inner.get("prediction")
    )
    if level:
        level = str(level).upper()
    elif score is not None:
        level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    # ── Detected threats ─────────────────────────────────────────────────────
    threats_raw = (
        inner.get("indicators")
        or inner.get("evidence")
        or final.get("evidence")
        or risk.get("evidence")
        or []
    )
    detected_threats = (
        "; ".join(str(t) for t in threats_raw if t)
        if isinstance(threats_raw, list) else str(threats_raw)
    ) or None

    # ── Explanation ───────────────────────────────────────────────────────────
    explanation = (
        final.get("summary")
        or final.get("explanation_summary")
        or inner.get("explanation")
        or analysis_data.get("explanation")
        or analysis_data.get("message")
        or risk.get("recommendation")
    )
    explanation = str(explanation).strip() if explanation else None

    # ── Geolocation & infrastructure telemetry ────────────────────────────────
    domain      = None
    ip_address  = None
    country     = None
    city        = None
    region      = None
    latitude    = None
    longitude   = None
    isp         = None
    organization = None
    asn         = None
    timezone    = None
    geo_source  = None
    abuse_confidence_score = None
    abuse_total_reports    = None
    abuse_usage_type       = None

    # Priority 1: threat_origin markers (richest source)
    threat_origin = (
        analysis_data.get("threat_origin")
        or inner.get("threat_origin")
        or {}
    )
    markers = threat_origin.get("markers") or []
    if markers and isinstance(markers, list):
        m = markers[0]  # primary marker
        domain       = m.get("label") or m.get("hostname")
        ip_address   = m.get("ip")
        country      = m.get("country")
        city         = m.get("city")
        region       = m.get("region")
        isp          = m.get("isp")
        organization = m.get("organization")
        asn          = m.get("asn")
        timezone     = m.get("timezone")
        geo_source   = m.get("geo_source")
        try:
            latitude  = float(m["latitude"])  if m.get("latitude")  is not None else None
            longitude = float(m["longitude"]) if m.get("longitude") is not None else None
        except (ValueError, TypeError):
            pass
        # AbuseIPDB
        abuse = m.get("abuse") or {}
        if abuse:
            abuse_confidence_score = abuse.get("confidence_score")
            abuse_total_reports    = abuse.get("total_reports")
            abuse_usage_type       = abuse.get("usage_type")

    # Priority 2: domain_info fallback
    domain_info = inner.get("domain_info") or analysis_data.get("domain_info") or {}
    if not domain and domain_info:
        domain = domain_info.get("root_domain") or domain_info.get("host")
    if not ip_address and domain_info:
        ip_address = domain_info.get("ip") or domain_info.get("resolved_ip")

    # Priority 3: geolocation dict fallback
    geo = inner.get("geolocation") or analysis_data.get("geolocation") or {}
    if geo and isinstance(geo, dict):
        if not country:     country  = geo.get("country")
        if not city:        city     = geo.get("city")
        if not region:      region   = geo.get("region")
        if not isp:         isp      = geo.get("isp")
        if not organization: organization = geo.get("org") or geo.get("organization")
        if not asn:         asn      = geo.get("asn")
        if latitude is None:
            try: latitude = float(geo["latitude"])
            except (KeyError, TypeError, ValueError): pass
        if longitude is None:
            try: longitude = float(geo["longitude"])
            except (KeyError, TypeError, ValueError): pass

    return {
        "risk_score":            score,
        "threat_level":          level,
        "detected_threats":      detected_threats,
        "explanation":           explanation,
        "domain":                domain,
        "ip_address":            ip_address,
        "country":               country,
        "city":                  city,
        "region":                region,
        "latitude":              latitude,
        "longitude":             longitude,
        "isp":                   isp,
        "organization":          organization,
        "asn":                   asn,
        "timezone":              timezone,
        "geo_source":            geo_source,
        "abuse_confidence_score": abuse_confidence_score,
        "abuse_total_reports":   abuse_total_reports,
        "abuse_usage_type":      abuse_usage_type,
    }


# ── Core persistence ──────────────────────────────────────────────────────────

def save_analysis(
    db: Session,
    analysis_data: dict,
    input_type: str,
    input_data: Optional[str] = None,
    custom_id: Optional[str] = None,
) -> Optional[Analysis]:
    """Persist an analysis record using an existing session. Returns the ORM object or None."""
    try:
        record_id = (
            custom_id
            or analysis_data.get("analysis_id")
            or f"SATYA-{uuid.uuid4().hex[:6].upper()}"
        )

        telemetry = extract_telemetry_fields(analysis_data, input_type, input_data)

        existing = db.query(Analysis).filter(Analysis.id == record_id).first()
        if existing:
            for k, v in telemetry.items():
                setattr(existing, k, v)
            if input_data:
                existing.input_data = input_data
            db.commit()
            db.refresh(existing)
            return existing

        db_record = Analysis(
            id=record_id,
            input_type=input_type or analysis_data.get("modality") or "unknown",
            input_data=input_data or analysis_data.get("filename"),
            **telemetry,
        )
        db.add(db_record)
        db.commit()
        db.refresh(db_record)
        logger.info(f"Analysis persisted: {record_id} ({input_type})")
        return db_record

    except Exception as exc:
        logger.warning(f"DB persistence error: {exc}")
        try:
            db.rollback()
        except Exception:
            pass
        return None


def save_analysis_safely(
    analysis_data: dict,
    input_type: str,
    input_data: Optional[str] = None,
    custom_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Self-contained, zero-crash persistence wrapper.
    Opens its own session. DB failure is a warning, never an exception.
    """
    try:
        from backend.database.database import SessionLocal
        if SessionLocal is None:
            return None
        with SessionLocal() as db:
            record = save_analysis(db, analysis_data, input_type, input_data, custom_id)
            if record:
                return record.to_dict()
    except Exception as exc:
        logger.warning(f"DB persistence skipped: {exc}")
    return None


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_analyses(db: Session, skip: int = 0, limit: int = 50) -> List[Analysis]:
    return (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_analysis_by_id(db: Session, analysis_id: str) -> Optional[Analysis]:
    return db.query(Analysis).filter(Analysis.id == analysis_id).first()
