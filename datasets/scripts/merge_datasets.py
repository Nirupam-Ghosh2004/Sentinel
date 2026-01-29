#!/usr/bin/env python3
"""
Merge all datasets into train/validation/test splits
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os

def merge_datasets():
    print("=" * 60)
    print("🔄 MERGING DATASETS")
    print("=" * 60)
    
    # Read all malicious URLs
    print("\n📖 Reading malicious URLs...")
    
    malicious_dfs = []
    
    # PhishTank
    if os.path.exists('../raw/phishtank.csv'):
        df_phish = pd.read_csv('../raw/phishtank.csv')
        df_phish = df_phish[['url', 'label', 'source']]
        malicious_dfs.append(df_phish)
        print(f"  ✅ PhishTank: {len(df_phish)} URLs")
    
    # OpenPhish
    if os.path.exists('../raw/openphish.csv'):
        df_open = pd.read_csv('../raw/openphish.csv')
        df_open = df_open[['url', 'label', 'source']]
        malicious_dfs.append(df_open)
        print(f"  ✅ OpenPhish: {len(df_open)} URLs")
    
    # URLhaus
    if os.path.exists('../raw/urlhaus_cleaned.csv'):
        df_haus = pd.read_csv('../raw/urlhaus_cleaned.csv')
        df_haus = df_haus[['url', 'label', 'source']]
        malicious_dfs.append(df_haus)
        print(f"  ✅ URLhaus: {len(df_haus)} URLs")
    
    # Combine malicious
    df_malicious = pd.concat(malicious_dfs, ignore_index=True)
    print(f"\n📊 Total malicious URLs: {len(df_malicious)}")
    
    # Read legitimate URLs
    print("\n📖 Reading legitimate URLs...")
    df_legitimate = pd.read_csv('../raw/legitimate_urls.csv')
    df_legitimate = df_legitimate[['url', 'label', 'source']]
    print(f"  ✅ Legitimate: {len(df_legitimate)} URLs")
    
    # Balance the dataset
    print("\n⚖️  Balancing dataset...")
    min_count = min(len(df_malicious), len(df_legitimate))
    print(f"  Sampling {min_count} URLs from each class")
    
    df_malicious_balanced = df_malicious.sample(n=min_count, random_state=42)
    df_legitimate_balanced = df_legitimate.sample(n=min_count, random_state=42)
    
    # Combine
    df_combined = pd.concat([df_malicious_balanced, df_legitimate_balanced], ignore_index=True)
    
    # Shuffle
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\n📊 Final dataset size: {len(df_combined)} URLs")
    print(f"  - Malicious: {len(df_malicious_balanced)}")
    print(f"  - Legitimate: {len(df_legitimate_balanced)}")
    
    # Split into train/val/test
    print("\n✂️  Splitting into train/validation/test...")
    
    # 70% train, 15% validation, 15% test
    train_val, test = train_test_split(df_combined, test_size=0.15, random_state=42, stratify=df_combined['label'])
    train, val = train_test_split(train_val, test_size=0.176, random_state=42, stratify=train_val['label'])  # 0.176 * 0.85 ≈ 0.15
    
    print(f"  ✅ Train: {len(train)} URLs")
    print(f"  ✅ Validation: {len(val)} URLs")
    print(f"  ✅ Test: {len(test)} URLs")
    
    # Save
    os.makedirs('../processed', exist_ok=True)
    
    train.to_csv('../processed/train.csv', index=False)
    val.to_csv('../processed/validation.csv', index=False)
    test.to_csv('../processed/test.csv', index=False)
    
    print("\n💾 Saved to:")
    print("  📁 ../processed/train.csv")
    print("  📁 ../processed/validation.csv")
    print("  📁 ../processed/test.csv")
    
    # Print statistics
    print("\n📊 DATASET STATISTICS")
    print("=" * 60)
    print(f"{'Split':<15} {'Total':<10} {'Malicious':<12} {'Legitimate':<12}")
    print("-" * 60)
    
    for name, df in [('Train', train), ('Validation', val), ('Test', test)]:
        total = len(df)
        malicious = len(df[df['label'] == 'malicious'])
        legitimate = len(df[df['label'] == 'legitimate'])
        print(f"{name:<15} {total:<10} {malicious:<12} {legitimate:<12}")
    
    print("=" * 60)

if __name__ == '__main__':
    merge_datasets()
    print("\n✅ DATASET MERGE COMPLETE!")
