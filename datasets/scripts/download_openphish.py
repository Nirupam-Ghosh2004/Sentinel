#!/usr/bin/env python3
"""
Download OpenPhish feed (active phishing URLs)
"""
import requests
import csv
import os
from datetime import datetime

def download_openphish():
    print("=" * 60)
    print("📥 DOWNLOADING OPENPHISH FEED")
    print("=" * 60)
    
    os.makedirs('../raw', exist_ok=True)
    
    url = "https://openphish.com/feed.txt"
    
    print(f"\n🌐 Fetching from: {url}")
    print("⏳ Downloading...\n")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        urls = response.text.strip().split('\n')
        urls = [u.strip() for u in urls if u.strip()]
        
        print(f"✅ Downloaded {len(urls)} phishing URLs")
        
        # Save as text file
        txt_path = '../raw/openphish.txt'
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"💾 Saved to: {txt_path}")
        
        # Also save as CSV for consistency
        csv_path = '../raw/openphish.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label', 'source', 'download_date'])
            
            for url in urls:
                writer.writerow([
                    url,
                    'malicious',
                    'openphish',
                    datetime.now().strftime('%Y-%m-%d')
                ])
        
        print(f"💾 CSV saved to: {csv_path}")
        print(f"📊 Total phishing URLs: {len(urls)}")
        
        return len(urls)
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading OpenPhish data: {e}")
        return 0
    except Exception as e:
        print(f"❌ Error processing data: {e}")
        return 0

if __name__ == '__main__':
    count = download_openphish()
    print("\n" + "=" * 60)
    print(f"✅ OPENPHISH DOWNLOAD COMPLETE: {count} URLs")
    print("=" * 60)
