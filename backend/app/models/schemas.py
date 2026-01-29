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
    timestamp: datetime = Field(default_factory=datetime.now)

class StatsResponse(BaseModel):
    """API statistics response"""
    total_checks: int
    malicious_detected: int
    legitimate_detected: int
    suspicious_detected: int
    uptime: str
