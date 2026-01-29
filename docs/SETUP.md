# Setup Guide

## System Requirements

- **OS:** Linux (Fedora/Ubuntu) or macOS
- **Python:** 3.10 or higher
- **Browser:** Chrome/Chromium 88+
- **RAM:** Minimum 4GB
- **Disk:** 500MB free space

## Detailed Installation

### Backend Setup

1. **Create virtual environment:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run server:**
```bash
python3 -m uvicorn app.main:app --reload
```

### Extension Setup

1. Open Chrome
2. Navigate to `chrome://extensions/`
3. Enable Developer Mode (top-right toggle)
4. Click "Load unpacked"
5. Select the `browser-extension/` directory

## Troubleshooting

**Backend won't start:**
- Check Python version: `python3 --version`
- Verify port 8000 is free: `lsof -i :8000`

**Extension not loading:**
- Check manifest.json syntax
- Look for errors in console
- Ensure all files are present

For more help, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
