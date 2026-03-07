"""
Anomaly Detection Routes — Zero-Day URL Analysis

Privacy-first endpoint that:
- Accepts a URL, extracts features, discards the raw URL
- Returns only the risk score and explanations
- No browsing history stored
- No external API calls
"""
from fastapi import APIRouter, HTTPException
from app.models.schemas import AnomalyCheckRequest, AnomalyCheckResponse
from app.services.risk_scorer import RiskScorer
import asyncio
import time

router = APIRouter(prefix="/api", tags=["Anomaly Detection"])

# Lazy-init scorer (loaded at first request)
_scorer = None

def _get_scorer() -> RiskScorer:
    global _scorer
    if _scorer is None:
        _scorer = RiskScorer()
    return _scorer


# In-memory stats (no persistence, resets on restart)
anomaly_stats = {
    "total_checks": 0,
    "normal": 0,
    "suspicious": 0,
    "high_anomaly": 0,
    "homographs_detected": 0,
    "start_time": time.time(),
}


@router.post("/anomaly", response_model=AnomalyCheckResponse)
async def check_anomaly(request: AnomalyCheckRequest):
    """
    Analyze a URL for structural anomalies.

    This endpoint:
    - Extracts features from the URL locally
    - Runs the Isolation Forest anomaly model
    - Performs homograph attack detection
    - Returns a 0-100 risk score with explainable reasons

    Privacy: The raw URL is discarded after feature extraction.
    No browsing history is stored. No external calls are made.
    """
    try:
        scorer = _get_scorer()

        if not scorer.is_ready():
            raise HTTPException(
                status_code=503,
                detail="Anomaly model not loaded. Run train_anomaly_model.py first."
            )

        # Score the URL
        # Run in thread pool (Isolation Forest scoring is CPU-bound)
        start = time.time()
        risk = await asyncio.to_thread(scorer.score, request.url)
        elapsed_ms = round((time.time() - start) * 1000, 1)

        # Update stats
        anomaly_stats["total_checks"] += 1

        if risk.risk_level == "HIGH_ANOMALY":
            anomaly_stats["high_anomaly"] += 1
        elif risk.risk_level == "SUSPICIOUS":
            anomaly_stats["suspicious"] += 1
        else:
            anomaly_stats["normal"] += 1

        if risk.homograph_flags:
            anomaly_stats["homographs_detected"] += 1

        return AnomalyCheckResponse(
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            reasons=risk.reasons,
            homograph_flags=risk.homograph_flags,
            feature_deviations=risk.feature_deviations,
            allow_override=risk.allow_override,
            processing_time_ms=elapsed_ms,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Anomaly analysis error: {str(e)}"
        )


@router.get("/anomaly/stats")
async def get_anomaly_stats():
    """Get anomaly detection statistics."""
    uptime = time.time() - anomaly_stats["start_time"]

    return {
        "total_checks": anomaly_stats["total_checks"],
        "normal": anomaly_stats["normal"],
        "suspicious": anomaly_stats["suspicious"],
        "high_anomaly": anomaly_stats["high_anomaly"],
        "homographs_detected": anomaly_stats["homographs_detected"],
        "uptime_hours": f"{uptime / 3600:.2f}",
    }
