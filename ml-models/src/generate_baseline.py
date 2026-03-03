#!/usr/bin/env python3
"""
Generate Baseline Statistics from Benign Browsing Data

Produces per-feature statistics (mean, std, min, max, percentiles) from
the legitimate URL dataset. Used by the risk scorer for:
  - Explaining WHICH features deviated
  - Computing z-scores for deviation severity
  - Providing human-readable anomaly explanations

Output: baseline_stats.pkl
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

import pandas as pd
import numpy as np
import joblib

from app.services.privacy_feature_extractor import PrivacyFeatureExtractor


def main():
    print("=" * 70)
    print(" GENERATING BASELINE STATISTICS")
    print("=" * 70)

    # Load legitimate URLs
    data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'datasets', 'processed')

    dfs = []
    for split in ['train.csv', 'validation.csv']:
        path = os.path.join(data_dir, split)
        if os.path.exists(path):
            df = pd.read_csv(path)
            legit = df[df['label'] == 'legitimate']
            dfs.append(legit)
            print(f"   {split}: {len(legit)} legitimate URLs")

    if not dfs:
        print(" No data files found!")
        sys.exit(1)

    all_legit = pd.concat(dfs, ignore_index=True)
    print(f"\n Total legitimate URLs: {len(all_legit)}")

    # Extract features
    extractor = PrivacyFeatureExtractor()
    print(f"\n Extracting {len(extractor.FEATURE_NAMES)} features...")

    features_list = []
    for i, url in enumerate(all_legit['url'].tolist()):
        features_list.append(extractor.extract(url))
        if (i + 1) % 10000 == 0:
            print(f"   Processed {i+1}/{len(all_legit)}...")

    feature_df = pd.DataFrame(features_list)

    # Compute statistics
    print("\n Computing statistics per feature...")
    stats = {}
    for name in extractor.FEATURE_NAMES:
        if name in feature_df.columns:
            col = feature_df[name]
            stats[name] = {
                'mean': float(col.mean()),
                'std': float(col.std()) if col.std() > 0 else 0.001,
                'min': float(col.min()),
                'max': float(col.max()),
                'p25': float(col.quantile(0.25)),
                'p50': float(col.quantile(0.50)),
                'p75': float(col.quantile(0.75)),
                'p95': float(col.quantile(0.95)),
                'p99': float(col.quantile(0.99)),
            }

    # Display summary
    print(f"\n{'Feature':<30} {'Mean':>10} {'Std':>10} {'Min':>10} {'Max':>10}")
    print("-" * 70)
    for name, s in stats.items():
        print(f"{name:<30} {s['mean']:>10.4f} {s['std']:>10.4f} "
              f"{s['min']:>10.4f} {s['max']:>10.4f}")

    # Save
    output_dirs = [
        os.path.join(os.path.dirname(__file__), '..', 'trained_models'),
        os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'app', 'ml_models'),
    ]

    for out_dir in output_dirs:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, 'baseline_stats.pkl')
        joblib.dump(stats, path)
        print(f"\n Saved: {path}")

    print("\n Baseline statistics generated!")


if __name__ == '__main__':
    main()
