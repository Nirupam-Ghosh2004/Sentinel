<p align="center">
  <img src="https://github.com/Nirupam-Ghosh2004/Sentinel/blob/main/readme-assets/banner.gif" alt="Header GIF">
</p>


**Real-time browser extension for detecting and blocking phishing, malware, and spam websites using Machine Learning and Domain Reputation Scoring.**

![Status](https://img.shields.io/badge/Status-Active-success)
![ML Model](https://img.shields.io/badge/ML%20Model-XGBoost-blue)
![Accuracy](https://img.shields.io/badge/Accuracy-99.89%25-brightgreen)

---

## 🎯 **Features**

### **Browser Extension**
-  Real-time URL scanning before page loads
-  Local heuristic-based detection (instant)
-  ML-powered backend integration
-  User-friendly warning pages
-  Statistics dashboard
-  Intelligent caching (1-hour TTL)

### **Backend API**
-  FastAPI REST endpoints
-  XGBoost ML model (99.89% accuracy)
-  50+ URL features extraction
-  Domain reputation scoring
-  Multi-layer threat detection

### **Machine Learning**
-  **137,268 URLs** in training dataset
-  **50 features** per URL
-  **XGBoost classifier** (99.89% test accuracy)
-  **0.02% false positive rate**
-  Cross-validation: 99.87% (±0.06%)

---

## 🏗️ **Architecture**
```
┌─────────────────────────────────────────────────────┐
│              BROWSER EXTENSION                      │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  Heuristics  │→ │    Cache     │→ │  Backend  │  │
│  │   (Instant)  │  │  (1hr TTL)   │  │  ML API   │  │
│  └──────────────┘  └──────────────┘  └───────────┘  │ 
└─────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────┐
│              BACKEND API (FastAPI)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │   Feature    │→ │  ML Model    │→ │Reputation │  │
│  │  Extraction  │  │  (XGBoost)   │  │  Scoring  │  │
│  └──────────────┘  └──────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────┘
                           ↓
              ┌────────────────────────┐
              │  FINAL DECISION        │
              │  (Malicious/Safe)      │
              └────────────────────────┘
```

---

## 📊 **Model Performance**

| Metric | Score |
|--------|-------|
| **Accuracy** | 99.89% |
| **Precision** | 99.98% |
| **Recall** | 99.81% |
| **F1 Score** | 99.89% |
| **False Positive Rate** | 0.02% (2 in 10,296) |
| **False Negative Rate** | 0.19% (20 in 10,295) |

**Training Details:**
- Dataset: 137,268 URLs (50% malicious, 50% legitimate)
- Features: 50 engineered features
- Algorithm: XGBoost with reputation validation
- Cross-validation: 5-fold, 99.87% ± 0.06%

---

## 🚀 **Installation**

### **Prerequisites**
- Python 3.10+
- Chrome/Chromium browser
- Fedora/Linux (or similar)

### **1. Clone Repository**
```bash
git clone https://github.com/Nirupam-Ghosh2004/Sentinel.git
cd Sentinel
```

### **2. Setup Backend**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start API server
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### **3. Install Browser Extension**
1. Open Chrome: `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `browser-extension/` folder

---

## 🧪 **Usage**

### **Backend API**

**Check URL:**
```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "status": "LEGITIMATE",
  "confidence": 0.98,
  "prediction_score": 0.02,
  "reason": "ML model + high reputation confirm legitimacy",
  "ml_raw_score": 0.015,
  "reputation_score": 95
}
```

**API Documentation:**
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### **Browser Extension**

- Extension automatically scans all page navigations
- Click shield icon to view statistics
- Blocked sites show warning page with details

---

## 📁 **Project Structure**
```
malicious-url-detector/
├── browser-extension/          # Chrome extension
│   ├── manifest.json
│   ├── background/
│   ├── popup/
│   ├── warning.html
│   └── assets/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── main.py
│   │   ├── routes/
│   │   ├── services/
│   │   │   ├── ml_service_final.py
│   │   │   ├── feature_extractor.py
│   │   │   └── reputation/
│   │   └── models/
│   └── requirements.txt
├── ml-models/                  # ML training pipeline
│   ├── src/
│   │   ├── feature_extractor_v2.py
│   │   ├── train_xgboost_v2.py
│   │   └── evaluate_model.py
│   ├── trained_models/
│   └── evaluation/
├── datasets/                   # Training data
│   ├── raw/
│   ├── processed/
│   └── scripts/
└── README.md
```

---

## 🔬 **Training Your Own Model**

### **1. Download Datasets**
```bash
cd datasets/scripts
python3 download_phishtank.py
python3 download_openphish.py
python3 download_legitimate.py
python3 merge_datasets.py
```

### **2. Train Model**
```bash
cd ml-models/src
source ../venv/bin/activate
python3 train_xgboost_v2.py
```

### **3. Deploy Model**
```bash
cp ml-models/trained_models/xgboost_model_v2.pkl backend/app/ml_models/xgboost_model.pkl
```

---

## 🛠️ **Technologies Used**

**Backend:**
- FastAPI (REST API)
- XGBoost (ML model)
- scikit-learn (ML pipeline)
- python-whois (domain reputation)
- dnspython (DNS checks)

**Frontend:**
- Chrome Extension Manifest V3
- JavaScript (ES6+)
- Chrome Storage API
- Web Request API

**ML Pipeline:**
- pandas, numpy (data processing)
- XGBoost (classification)
- matplotlib, seaborn (visualization)

---


---

## 🤝 **Contributing**

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📄 **License**

This project is licensed under the MIT License.

---

## 👤 **Author**

**Nirupam Ghosh**
- GitHub: [@Nirupam-Ghosh2004](https://github.com/Nirupam-Ghosh2004)
- Email: nirupam.ghosh0423@gmail.com

---

## 🙏 **Acknowledgments**

- PhishTank for phishing URL dataset
- OpenPhish for real-time phishing feed
- Tranco for top website rankings
- URLhaus for malware distribution URLs

---

## 📊 **Statistics**

![GitHub stars](https://img.shields.io/github/stars/Nirupam-Ghosh2004/Sentinel)
![GitHub forks](https://img.shields.io/github/forks/Nirupam-Ghosh2004/Sentinel)
![GitHub issues](https://img.shields.io/github/issues/Nirupam-Ghosh2004/Sentinel)
