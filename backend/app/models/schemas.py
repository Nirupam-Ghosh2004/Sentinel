"""
Pydantic models for request/response validation
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Dict
from datetime import datetime

class URLCheckRequest(BaseModel):
    """Request model for URL checking"""
    url: str = Field(..., description="URL to check", min_length=1)
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://suspicious-site.tk"
            }
        }

class URLCheckResponse(BaseModel):
    """Response model for URL checking"""
    url: str
    status: str  # "MALICIOUS", "SUSPICIOUS", "LEGITIMATE"
    confidence: float
    prediction_score: float
    reason: str
    features: Optional[Dict] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://malicious-site.tk",
                "status": "MALICIOUS",
                "confidence": 0.95,
                "prediction_score": 0.95,
                "reason": "Suspicious TLD and high entropy domain name",
                "timestamp": "2024-01-28T10:30:00"
            }
        }

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    model_loaded: bool
    anomaly_model_loaded: bool = False
    timestamp: datetime = Field(default_factory=datetime.now)

class StatsResponse(BaseModel):
    """API statistics response"""
    total_checks: int
    malicious_detected: int
    legitimate_detected: int
    suspicious_detected: int
    uptime: str


class AnomalyCheckRequest(BaseModel):
    """Request model for anomaly-based URL checking"""
    url: str = Field(..., description="URL to analyze for anomalies", min_length=1)

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://xn--80ak6aa92e.com/login/verify"
            }
        }


class AnomalyCheckResponse(BaseModel):
    """Response model for anomaly detection"""
    risk_score: int = Field(ge=0, le=100, description="Risk score 0-100")
    risk_level: str  # NORMAL / SUSPICIOUS / HIGH_ANOMALY
    reasons: list = Field(default_factory=list)
    homograph_flags: list = Field(default_factory=list)
    feature_deviations: Dict = Field(default_factory=dict)
    allow_override: bool = True
    processing_time_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)

    class Config:
        json_schema_extra = {
            "example": {
                "risk_score": 84,
                "risk_level": "HIGH_ANOMALY",
                "reasons": [
                    "Domain name randomness is significantly above baseline (4.2σ deviation)",
                    "Number of subdomains is notably above baseline (3.1σ deviation)"
                ],
                "homograph_flags": ["Punycode (xn--) domain detected"],
                "feature_deviations": {},
                "allow_override": True,
                "processing_time_ms": 12.5,
                "timestamp": "2026-03-01T19:30:00"
            }
        }
