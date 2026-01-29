#!/usr/bin/env python3
"""
Download PhishTank verified phishing URLs
"""
import requests
import json
import csv
from datetime import datetime
import os

def download_phishtank():
    print("=" * 60)
    print("📥 DOWNLOADING PHISHTANK DATABASE")
    print("=" * 60)
    
    # Create raw directory if it doesn't exist
    os.makedirs('../raw', exist_ok=True)
    
    # PhishTank verified phishing URLs (JSON format)
    url = "http://data.phishtank.com/data/online-valid.json"
    
    print(f"\n🌐 Fetching from: {url}")
    print("⏳ This may take a minute...\n")
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        data = response.json()
        
        print(f"✅ Downloaded {len(data)} phishing URLs")
        
        # Save to CSV
        csv_path = '../raw/phishtank.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label', 'source', 'verified', 'submission_time', 'phish_id'])
            
            for entry in data:
                writer.writerow([
                    entry.get('url', ''),
                    'malicious',
                    'phishtank',
                    entry.get('verified', 'yes'),
                    entry.get('submission_time', ''),
                    entry.get('phish_id', '')
                ])
        
        print(f"💾 Saved to: {csv_path}")
        print(f"📊 Total phishing URLs: {len(data)}")
        
        # Also save raw JSON for reference
        json_path = '../raw/phishtank.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        print(f"💾 Raw JSON saved to: {json_path}")
        
        return len(data)
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading PhishTank data: {e}")
        return 0
    except Exception as e:
        print(f"❌ Error processing data: {e}")
        return 0

if __name__ == '__main__':
    count = download_phishtank()
    print("\n" + "=" * 60)
    print(f"✅ PHISHTANK DOWNLOAD COMPLETE: {count} URLs")
    print("=" * 60)
