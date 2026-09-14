from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field


class AnalysisBase(BaseModel):
    input_type: str = Field(..., description="Modality: message, url, email, image, audio, video, call")
    input_data: Optional[str] = Field(None, description="Input text, URL, or original filename")
    risk_score: Optional[int] = Field(None, description="0-100 overall threat risk score")
    threat_level: Optional[str] = Field(None, description="Risk classification: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    detected_threats: Optional[str] = Field(None, description="Comma-separated or JSON list of threat indicators")
    explanation: Optional[str] = Field(None, description="Summary or rationale for the classification")
    domain: Optional[str] = Field(None, description="Target domain or hostname")
    ip_address: Optional[str] = Field(None, description="Target or mail server public IP address")
    country: Optional[str] = Field(None, description="Geolocated country")
    city: Optional[str] = Field(None, description="Geolocated city")
    latitude: Optional[float] = Field(None, description="Approximate infrastructure latitude")
    longitude: Optional[float] = Field(None, description="Approximate infrastructure longitude")


class AnalysisCreate(AnalysisBase):
    id: Optional[str] = Field(None, description="Optional custom or generated analysis ID")


class AnalysisResponse(AnalysisBase):
    id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisListResponse(BaseModel):
    total: int
    analyses: List[AnalysisResponse]
