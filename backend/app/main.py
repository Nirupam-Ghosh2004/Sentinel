"""
FastAPI Main Application - ML-First with Reputation Validation
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.routes import check, anomaly
from app.models.schemas import HealthResponse
from app.services.ml_service_final import get_ml_service
from app.services.anomaly_detector import get_anomaly_detector

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="3.0.0",
    description="Zero-Day Anomaly Detection + ML-Based Malicious URL Detection",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(check.router)
app.include_router(anomaly.router)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("=" * 60)
    print(f"{settings.app_name} v3.0.0")
    print("  Zero-Day Anomaly Detection Engine")
    print("  ML-First Classification")
    print("  Reputation Validation Layer")
    print("=" * 60)
    
    # Load ML classifier
    ml_service = get_ml_service()
    if ml_service.is_loaded():
        print("ML model + reputation service ready.")
    else:
        print("[WARN] ML classifier not loaded (optional).")
    
    # Load anomaly detector
    anomaly_detector = get_anomaly_detector()
    if anomaly_detector.is_loaded():
        print("Anomaly detection engine ready.")
    else:
        print("[WARN] Anomaly model not loaded. Run train_anomaly_model.py.")
    
    print("=" * 60)
    print(f"Server: http://{settings.host}:{settings.port}")
    print(f"Docs:   http://{settings.host}:{settings.port}/docs")
    print("=" * 60)

@app.get("/", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    ml_service = get_ml_service()
    
    anomaly_detector = get_anomaly_detector()
    
    return HealthResponse(
        status="healthy",
        version="3.0.0",
        model_loaded=ml_service.is_loaded(),
        anomaly_model_loaded=anomaly_detector.is_loaded()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )