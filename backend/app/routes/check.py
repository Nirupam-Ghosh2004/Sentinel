"""
URL checking routes - ML-First approach
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from app.models.schemas import URLCheckRequest, URLCheckResponse
from app.services.ml_service_final import get_ml_service
import time

router = APIRouter(prefix="/api", tags=["URL Checking"])

stats = {
    "total_checks": 0,
    "malicious": 0,
    "suspicious": 0,
    "legitimate": 0,
    "ml_predictions": 0,
    "reputation_adjustments": 0,
    "start_time": time.time()
}

@router.post("/check", response_model=URLCheckResponse)
async def check_url(
    request: URLCheckRequest,
    use_reputation: bool = Query(True, description="Enable reputation validation"),
    ml_service = Depends(get_ml_service)
):
    """
    Check URL using ML-First approach
    
    - ML model always runs (your trained model!)
    - Reputation provides validation/adjustment
    - Full transparency in response
    """
    try:
        # Get ML prediction with optional reputation validation
        result = ml_service.predict(request.url, use_reputation=use_reputation)
        
        # Update statistics
        stats["total_checks"] += 1
        stats["ml_predictions"] += 1
        
        if result.get('adjustment_applied'):
            stats["reputation_adjustments"] += 1
        
        if result['status'] == "MALICIOUS":
            stats["malicious"] += 1
        elif result['status'] == "SUSPICIOUS":
            stats["suspicious"] += 1
        else:
            stats["legitimate"] += 1
        
        # Build response
        response = URLCheckResponse(
            url=request.url,
            status=result['status'],
            confidence=result['confidence'],
            prediction_score=result['prediction_score'],
            reason=result['reason'],
            features=result.get('transparency', {})
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error: {str(e)}"
        )

@router.get("/stats")
async def get_stats():
    """Get API statistics"""
    uptime = time.time() - stats["start_time"]
    
    return {
        "total_checks": stats["total_checks"],
        "ml_predictions_made": stats["ml_predictions"],
        "reputation_adjustments": stats["reputation_adjustments"],
        "malicious_detected": stats["malicious"],
        "suspicious_detected": stats["suspicious"],
        "legitimate_detected": stats["legitimate"],
        "uptime_hours": f"{uptime / 3600:.2f}"
    }