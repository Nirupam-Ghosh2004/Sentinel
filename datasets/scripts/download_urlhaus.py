#!/usr/bin/env python3
"""
Download URLhaus malware distribution URLs
"""
import requests
import csv
import os
from datetime import datetime

def download_urlhaus():
    print("=" * 60)
    print("📥 DOWNLOADING URLHAUS DATABASE")
    print("=" * 60)
    
    os.makedirs('../raw', exist_ok=True)
    
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    
    print(f"\n🌐 Fetching from: {url}")
    print("⏳ Downloading...\n")
    
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        
        # Save raw CSV
        csv_path = '../raw/urlhaus.csv'
        with open(csv_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        # Count URLs (skip comment lines)
        lines = response.text.strip().split('\n')
        urls = [line for line in lines if not line.startswith('#') and line.strip()]
        
        print(f"✅ Downloaded {len(urls)} malware URLs")
        print(f"💾 Saved to: {csv_path}")
        
        # Create cleaned version
        cleaned_path = '../raw/urlhaus_cleaned.csv'
        with open(cleaned_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label', 'source', 'download_date'])
            
            for line in urls[1:]:  # Skip header
                parts = line.split(',', 1)
                if len(parts) > 0 and parts[0].strip():
                    # URLhaus format: id,dateadded,url,...
                    # We extract just the URL
                    cols = line.split('","')
                    if len(cols) > 2:
                        url_field = cols[2].strip('"')
                        writer.writerow([
                            url_field,
                            'malicious',
                            'urlhaus',
                            datetime.now().strftime('%Y-%m-%d')
                        ])
        
        print(f"💾 Cleaned CSV saved to: {cleaned_path}")
        print(f"📊 Total malware URLs: {len(urls) - 1}")
        
        return len(urls) - 1
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading URLhaus data: {e}")
        return 0
    except Exception as e:
        print(f"❌ Error processing data: {e}")
        return 0

if __name__ == '__main__':
    count = download_urlhaus()
    print("\n" + "=" * 60)
    print(f"✅ URLHAUS DOWNLOAD COMPLETE: {count} URLs")
    print("=" * 60)
