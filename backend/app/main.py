"""
FastAPI Main Application - ML-First with Reputation Validation
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.routes import check
from app.models.schemas import HealthResponse
from app.services.ml_service_final import get_ml_service

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="2.1.0",
    description="ML-First Malicious URL Detection with Reputation Validation",
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

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("=" * 60)
    print(f"🚀 {settings.app_name} v2.1.0")
    print("   🤖 ML-FIRST Architecture")
    print("   ✨ Reputation Validation Layer")
    print("=" * 60)
    
    ml_service = get_ml_service()
    
    if ml_service.is_loaded():
        print("✅ ML Model + Reputation Service Ready!")
    else:
        print("❌ Failed to load services!")
    
    print("=" * 60)
    print(f"📡 Server: http://{settings.host}:{settings.port}")
    print(f"📚 Docs: http://{settings.host}:{settings.port}/docs")
    print("=" * 60)

@app.get("/", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    ml_service = get_ml_service()
    
    return HealthResponse(
        status="healthy",
        version="2.1.0",
        model_loaded=ml_service.is_loaded()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )