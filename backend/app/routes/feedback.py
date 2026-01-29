"""
User Feedback Routes
Allow users to report false positives/negatives
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
import json
import os

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])

class FeedbackRequest(BaseModel):
    url: str
    predicted_status: str  # What model said
    actual_status: str  # What user says (legitimate/malicious)
    user_comment: Optional[str] = None

# Simple file-based storage (use database in production)
FEEDBACK_FILE = "feedback_data.json"

@router.post("/report")
async def submit_feedback(feedback: FeedbackRequest):
    """Submit user feedback for false positive/negative"""
    
    # Load existing feedback
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, 'r') as f:
            feedback_data = json.load(f)
    else:
        feedback_data = []
    
    # Add new feedback
    feedback_entry = {
        'url': feedback.url,
        'predicted_status': feedback.predicted_status,
        'actual_status': feedback.actual_status,
        'user_comment': feedback.user_comment,
        'timestamp': datetime.now().isoformat()
    }
    
    feedback_data.append(feedback_entry)
    
    # Save feedback
    with open(FEEDBACK_FILE, 'w') as f:
        json.dump(feedback_data, f, indent=2)
    
    # If false positive, add to temporary whitelist
    if feedback.predicted_status == 'MALICIOUS' and feedback.actual_status == 'legitimate':
        add_to_whitelist(feedback.url)
    
    return {
        'status': 'success',
        'message': 'Thank you for your feedback!'
    }

def add_to_whitelist(url: str):
    """Add domain to dynamic whitelist"""
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Load whitelist
    whitelist_file = "dynamic_whitelist.json"
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as f:
            whitelist = json.load(f)
    else:
        whitelist = []
    
    if hostname not in whitelist:
        whitelist.append(hostname)
        
        with open(whitelist_file, 'w') as f:
            json.dump(whitelist, f, indent=2)