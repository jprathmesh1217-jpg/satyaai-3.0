import uuid
import logging
from typing import Optional, List, Any
from sqlalchemy.orm import Session
from backend.database.models import Analysis
from backend.database.schemas import AnalysisCreate

logger = logging.getLogger("satyaai.database_service")


def extract_telemetry_fields(analysis_data: dict, input_type: str, input_data: Optional[str] = None) -> dict:
    """Extract and normalize threat analysis and geolocation metrics for database persistence."""
    risk = analysis_data.get("risk_assessment") or analysis_data.get("risk") or {}
    analysis_inner = analysis_data.get("analysis") or {}
    final = analysis_data.get("final_analysis") or {}

    # 1. Risk Score
    score = (
        risk.get("final_score")
        if risk.get("final_score") is not None
        else risk.get("score")
        if risk.get("score") is not None
        else analysis_data.get("risk_score")
        if analysis_data.get("risk_score") is not None
        else analysis_inner.get("probability")
        if analysis_inner.get("probability") is not None
        else analysis_inner.get("scam_probability")
    )
    if score is not None:
        try:
            score = int(round(float(score)))
        except (ValueError, TypeError):
            score = None

    # 2. Threat Level
    level = (
        risk.get("risk_level")
        or risk.get("level")
        or analysis_data.get("risk_level")
        or (analysis_inner.get("ml") or {}).get("prediction_label")
        or analysis_inner.get("prediction")
        or ("HIGH" if (score is not None and score >= 60) else "MEDIUM" if (score is not None and score >= 30) else "LOW")
    )
    if level:
        level = str(level).upper()

    # 3. Detected threats / indicators
    threats_list = (
        analysis_inner.get("indicators")
        or analysis_inner.get("evidence")
        or final.get("evidence")
        or risk.get("evidence")
        or []
    )
    if isinstance(threats_list, list):
        detected_threats = "; ".join(str(t) for t in threats_list if t) or None
    else:
        detected_threats = str(threats_list) if threats_list else None

    # 4. Explanation
    explanation = (
        final.get("summary")
        or final.get("explanation_summary")
        or analysis_inner.get("explanation")
        or analysis_data.get("explanation")
        or analysis_data.get("message")
        or (risk.get("recommendation") if risk.get("recommendation") else None)
    )
    if explanation:
        explanation = str(explanation).strip()

    # 5. Geolocation & Threat Origin Telemetry
    domain = None
    ip_address = None
    country = None
    city = None
    latitude = None
    longitude = None

    threat_origin = analysis_data.get("threat_origin") or analysis_inner.get("threat_origin") or {}
    markers = threat_origin.get("markers") or []

    if markers and isinstance(markers, list):
        primary_marker = markers[0]
        domain = primary_marker.get("label")
        ip_address = primary_marker.get("ip")
        country = primary_marker.get("country")
        city = primary_marker.get("city")
        try:
            latitude = float(primary_marker["latitude"]) if primary_marker.get("latitude") is not None else None
            longitude = float(primary_marker["longitude"]) if primary_marker.get("longitude") is not None else None
        except (ValueError, TypeError):
            pass

    # Fallback to domain_info or direct geolocation
    domain_info = analysis_inner.get("domain_info") or analysis_data.get("domain_info") or {}
    if not domain and domain_info:
        domain = domain_info.get("root_domain") or domain_info.get("domain") or domain_info.get("host")
    if not ip_address and domain_info:
        ip_address = domain_info.get("ip")

    geo = analysis_inner.get("geolocation") or analysis_data.get("geolocation") or {}
    if geo and isinstance(geo, dict):
        if not country:
            country = geo.get("country")
        if not city:
            city = geo.get("city")
        if latitude is None and geo.get("latitude") is not None:
            try:
                latitude = float(geo["latitude"])
            except (ValueError, TypeError):
                pass
        if longitude is None and geo.get("longitude") is not None:
            try:
                longitude = float(geo["longitude"])
            except (ValueError, TypeError):
                pass

    return {
        "risk_score": score,
        "threat_level": level,
        "detected_threats": detected_threats,
        "explanation": explanation,
        "domain": domain,
        "ip_address": ip_address,
        "country": country,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
    }


def save_analysis(
    db: Session,
    analysis_data: dict,
    input_type: str,
    input_data: Optional[str] = None,
    custom_id: Optional[str] = None,
) -> Optional[Analysis]:
    """Persist an analysis record to PostgreSQL using an existing database session."""
    try:
        record_id = (
            custom_id
            or analysis_data.get("analysis_id")
            or f"SATYA-{uuid.uuid4().hex[:6].upper()}"
        )

        telemetry = extract_telemetry_fields(analysis_data, input_type, input_data)

        # Check if record already exists to avoid primary key conflicts
        existing = db.query(Analysis).filter(Analysis.id == record_id).first()
        if existing:
            for k, v in telemetry.items():
                setattr(existing, k, v)
            if input_data:
                existing.input_data = input_data
            db.commit()
            db.refresh(existing)
            return existing

        db_analysis = Analysis(
            id=record_id,
            input_type=input_type or analysis_data.get("modality") or "unknown",
            input_data=input_data or analysis_data.get("filename"),
            **telemetry,
        )
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)
        logger.info(f"Analysis successfully persisted in satyaai_db: {record_id}")
        return db_analysis
    except Exception as exc:
        logger.warning(f"Database persistence error: {exc}. Rolling back transaction.")
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
    """Self-contained safe persistence helper with internal session management and zero-crash guarantee."""
    try:
        from backend.database.database import SessionLocal
        if SessionLocal is None:
            return None
        with SessionLocal() as db:
            record = save_analysis(db, analysis_data, input_type, input_data, custom_id)
            if record:
                return record.to_dict()
    except Exception as exc:
        logger.warning(f"Database persistence skipped (PostgreSQL unavailable or error): {exc}")
    return None


def get_analyses(db: Session, skip: int = 0, limit: int = 50) -> List[Analysis]:
    """Fetch stored analyses ordered by newest first."""
    return (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_analysis_by_id(db: Session, analysis_id: str) -> Optional[Analysis]:
    """Retrieve an analysis record by its primary key ID."""
    return db.query(Analysis).filter(Analysis.id == analysis_id).first()
