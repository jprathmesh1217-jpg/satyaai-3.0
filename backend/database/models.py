from datetime import datetime
from sqlalchemy import Column, String, Text, Integer, Float, DateTime
from backend.database.database import Base


class Analysis(Base):
    """SQLAlchemy model representing a completed threat analysis in SatyaAI."""
    __tablename__ = "analyses"

    id = Column(String(64), primary_key=True, index=True)
    input_type = Column(String(50), nullable=False, index=True)
    input_data = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    threat_level = Column(String(50), nullable=True)
    detected_threats = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "input_type": self.input_type,
            "input_data": self.input_data,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "detected_threats": self.detected_threats,
            "explanation": self.explanation,
            "domain": self.domain,
            "ip_address": self.ip_address,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
