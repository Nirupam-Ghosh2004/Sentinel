"""
Configuration for the API
"""
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # API Settings
    app_name: str = "Malicious URL Detection API"
    app_version: str = "1.0.0"
    debug: bool = True
    
    # Server Settings
    host: str = "127.0.0.1"
    port: int = 8000
    
    # CORS Settings
    allowed_origins: list = [
        "http://localhost:3000",
        "chrome-extension://*",
        "*"
    ]
    
    # ML Model Settings
    model_path: str = "app/ml_models/xgboost_model.pkl"
    feature_names_path: str = "app/ml_models/feature_names.pkl"
    
    # Prediction Thresholds - ADJUSTED
    malicious_threshold: float = 0.70  # Raised from 0.50 to 0.70
    suspicious_threshold: float = 0.40  # Raised from 0.30 to 0.40
    
    # Rate Limiting
    rate_limit: int = 100
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
