from datetime import datetime
from sqlalchemy import Column, String, Text, Integer, Float, DateTime
from backend.database.database import Base


class Analysis(Base):
    """SQLAlchemy model representing a completed threat analysis in SatyaAI."""
    __tablename__ = "analyses"

    id             = Column(String(64),  primary_key=True, index=True)
    input_type     = Column(String(50),  nullable=False, index=True)
    input_data     = Column(Text,        nullable=True)
    risk_score     = Column(Integer,     nullable=True)
    threat_level   = Column(String(50),  nullable=True)
    detected_threats = Column(Text,      nullable=True)
    explanation    = Column(Text,        nullable=True)

    # Infrastructure geolocation
    domain         = Column(String(255), nullable=True)
    ip_address     = Column(String(64),  nullable=True)
    country        = Column(String(100), nullable=True)
    city           = Column(String(100), nullable=True)
    region         = Column(String(100), nullable=True)
    latitude       = Column(Float,       nullable=True)
    longitude      = Column(Float,       nullable=True)

    # Extended telemetry (added for IPinfo / AbuseIPDB integration)
    isp            = Column(String(255), nullable=True)
    organization   = Column(String(255), nullable=True)
    asn            = Column(String(50),  nullable=True)
    timezone       = Column(String(100), nullable=True)
    geo_source     = Column(String(50),  nullable=True)   # "IPinfo" | "ip-api.com"

    # AbuseIPDB reputation
    abuse_confidence_score = Column(Integer, nullable=True)
    abuse_total_reports    = Column(Integer, nullable=True)
    abuse_usage_type       = Column(String(100), nullable=True)

    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "input_type":            self.input_type,
            "input_data":            self.input_data,
            "risk_score":            self.risk_score,
            "threat_level":          self.threat_level,
            "detected_threats":      self.detected_threats,
            "explanation":           self.explanation,
            "domain":                self.domain,
            "ip_address":            self.ip_address,
            "country":               self.country,
            "city":                  self.city,
            "region":                self.region,
            "latitude":              self.latitude,
            "longitude":             self.longitude,
            "isp":                   self.isp,
            "organization":          self.organization,
            "asn":                   self.asn,
            "timezone":              self.timezone,
            "geo_source":            self.geo_source,
            "abuse_confidence_score": self.abuse_confidence_score,
            "abuse_total_reports":   self.abuse_total_reports,
            "abuse_usage_type":      self.abuse_usage_type,
            "created_at":            self.created_at.isoformat() if self.created_at else None,
        }
