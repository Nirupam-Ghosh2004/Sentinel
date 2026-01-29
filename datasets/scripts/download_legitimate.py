#!/usr/bin/env python3
"""
Download Tranco top websites list (legitimate URLs)
"""
import requests
import csv
import zipfile
import os
from io import BytesIO

def download_legitimate():
    print("=" * 60)
    print("📥 DOWNLOADING TRANCO TOP WEBSITES")
    print("=" * 60)
    
    os.makedirs('../raw', exist_ok=True)
    
    # Tranco list (replacement for Alexa Top 1M)
    url = "https://tranco-list.eu/top-1m.csv.zip"
    
    print(f"\n🌐 Fetching from: {url}")
    print("⏳ This may take a minute...\n")
    
    try:
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        
        print("✅ Downloaded zip file")
        print("📦 Extracting...")
        
        # Extract ZIP file
        with zipfile.ZipFile(BytesIO(response.content)) as zip_ref:
            # Extract to raw directory
            zip_ref.extractall('../raw/')
            
        print("✅ Extracted successfully")
        
        # Read the CSV and convert to our format
        input_path = '../raw/top-1m.csv'
        output_path = '../raw/legitimate_urls.csv'
        
        count = 0
        with open(input_path, 'r', encoding='utf-8') as infile:
            with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(['url', 'label', 'source', 'rank'])
                
                reader = csv.reader(infile)
                for row in reader:
                    if len(row) >= 2:
                        rank, domain = row[0], row[1]
                        # Add https:// prefix
                        url = f"https://{domain}"
                        writer.writerow([url, 'legitimate', 'tranco', rank])
                        count += 1
                        
                        # Limit to top 100k for now (adjust as needed)
                        if count >= 100000:
                            break
        
        print(f"💾 Saved to: {output_path}")
        print(f"📊 Total legitimate URLs: {count}")
        
        # Clean up
        if os.path.exists(input_path):
            os.remove(input_path)
            print("🗑️  Cleaned up temporary files")
        
        return count
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading Tranco data: {e}")
        return 0
    except Exception as e:
        print(f"❌ Error processing data: {e}")
        return 0

if __name__ == '__main__':
    count = download_legitimate()
    print("\n" + "=" * 60)
    print(f"✅ TRANCO DOWNLOAD COMPLETE: {count} URLs")
    print("=" * 60)
