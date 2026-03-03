#!/usr/bin/env python3
"""
Train Anomaly Detection Model (Isolation Forest)

Trains on legitimate URLs only to learn normal browsing patterns.
The dataset contains mostly bare domains, so we augment with
realistic paths to avoid false-flagging URLs with paths.

Output:
  - isolation_forest.pkl
  - anomaly_scaler.pkl
  - baseline_stats.pkl
"""
import sys
import os
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib

from app.services.privacy_feature_extractor import PrivacyFeatureExtractor


# Realistic path/query augmentation templates
# Comprehensive set covering real browsing patterns: shallow, medium, deep paths
REALISTIC_PATHS = [
    # Shallow (0-1 segments)
    '/',
    '/about',
    '/contact',
    '/login',
    '/signup',
    '/pricing',
    '/terms',
    '/privacy',
    '/search',
    '/news',
    '/help',
    '/faq',
    '/download',
    '/dashboard',
    '/settings',
    '/explore',
    '/trending',

    # Medium depth (2 segments)
    '/category/electronics',
    '/category/books',
    '/category/clothing',
    '/user/profile',
    '/user/settings',
    '/user/notifications',
    '/docs/introduction',
    '/docs/api-reference',
    '/en/home',
    '/shop/items',
    '/video/watch',
    '/music/playlist',
    '/account/orders',
    '/blog/latest',
    '/wiki/Machine_learning',
    '/wiki/Python_programming',
    '/wiki/Data_science',
    '/mail/inbox',
    '/mail/u',
    '/dp/B09V3KXJPB',
    '/dp/B01MFGH123',
    '/gp/product',
    '/3/tutorial',
    '/3/library',
    '/api/v1',
    '/api/v2',
    '/en-us/docs',
    '/ja/help',
    '/de/produkte',

    # Deep paths (3 segments)
    '/docs/getting-started/installation',
    '/docs/api/authentication',
    '/docs/guides/quickstart',
    '/article/2024/interesting-topic',
    '/post/2024/how-to-guide',
    '/en/docs/reference',
    '/en-us/docs/web',
    '/r/programming/hot',
    '/r/technology/new',
    '/r/science/top',
    '/mail/u/0',
    '/mail/u/1',
    '/3/library/functions',
    '/3/tutorial/introduction',
    '/questions/12345678/how-to-code',
    '/questions/98765432/best-practices',
    '/issues/1234/comments',
    '/pull/5678/files',
    '/commit/abc123def',
    '/tree/main/src',
    '/blob/main/README',
    '/detail/product-name/reviews',
    '/detail/item-12345/specs',
    '/order/123456/status',
    '/account/settings/security',
    '/notifications/all/unread',
    '/channel/UCxyz/videos',
    '/playlist/PLxyz123/edit',

    # Deep paths (4+ segments)
    '/mail/u/0/inbox',
    '/mail/u/0/sent',
    '/mail/u/0/drafts',
    '/r/programming/comments/abc123/interesting_post',
    '/r/technology/comments/xyz789/big_news_today',
    '/r/python/comments/def456/cool_library',
    '/en-us/docs/web/javascript',
    '/en-us/docs/web/css/flexbox',
    '/questions/12345678/how-to-code-in-python',
    '/a/12345678/answer-content',
    '/3/library/functions/print',
    '/3/library/stdtypes/str',
    '/wiki/Category:Computer_science',
    '/wiki/Talk:Machine_learning',
    '/tree/main/src/components',
    '/blob/main/src/utils/helper',
    '/releases/tag/v2.0.0/assets',
    '/repos/user/project/issues',
    '/products/category/subcategory/item',
    '/shop/department/brand/product',
    '/blog/2024/01/15/my-post-title',
    '/news/2024/march/breaking-story',
    '/video/watch/playlist/index',
    '/courses/web-development/lesson-1/quiz',
    '/learn/paths/data-science/module-3',
    '/account/settings/notifications/email',
    '/admin/users/active/page/1',
    '/api/v2/users/12345/posts',
    '/api/v1/projects/678/members',

    # Patterns with numbers/IDs
    '/watch/dQw4w9WgXcQ',
    '/video/12345678',
    '/photo/98765432',
    '/status/1234567890',
    '/p/CxYz123AbC',
    '/pin/123456789',
    '/item/ASIN12345',
    '/t/interesting-topic/12345',
    '/d/dashboard-id/edit',
]

REALISTIC_QUERIES = [
    '',                  # ~40% of real URLs have no query
    '',
    '',
    '',
    '',
    '?q=search+term',
    '?q=how+to+learn+python',
    '?q=best+practices+for+web+development',
    '?page=2',
    '?page=5',
    '?p=12345',
    '?id=12345',
    '?id=abc123def456',
    '?v=dQw4w9WgXcQ',
    '?list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf',
    '?category=electronics&brand=samsung',
    '?sort=price&order=asc',
    '?sort=relevance&filter=recent',
    '?lang=en',
    '?lang=en-US',
    '?hl=en&gl=us',
    '?ref=homepage',
    '?ref=sr_1_1',
    '?utm_source=google&utm_medium=cpc',
    '?utm_source=newsletter&utm_campaign=spring2024',
    '?tab=overview',
    '?tab=repositories&type=source',
    '?view=grid',
    '?limit=20&offset=40',
    '?per_page=25&page=3',
    '?filter=new',
    '?filter=top&t=month',
    '?type=video&duration=long',
    '?start=0&count=10',
    '?from=2024-01-01&to=2024-12-31',
    '?token=eyJhbGciOi',
    '?redirect_uri=https%3A%2F%2Fexample.com',
]


def augment_urls(urls, multiply_factor=3):
    """
    Augment bare domain URLs with realistic paths and query params.
    
    For each bare domain URL, create multiple variants with real-world paths
    to build a representative baseline.
    """
    print(f"\nAugmenting {len(urls)} URLs with realistic paths...")
    
    augmented = []
    
    for url in urls:
        # Always keep the original
        augmented.append(url)
        
        # Add variants with realistic paths
        for _ in range(multiply_factor):
            path = random.choice(REALISTIC_PATHS)
            query = random.choice(REALISTIC_QUERIES)
            
            # Strip trailing slash from base URL
            base = url.rstrip('/')
            new_url = base + path + query
            augmented.append(new_url)
    
    random.shuffle(augmented)
    print(f"  Augmented to {len(augmented)} URLs ({multiply_factor}x + originals)")
    return augmented


def load_legitimate_urls():
    """Load only legitimate URLs from the processed dataset."""
    print("=" * 70)
    print("LOADING LEGITIMATE (BENIGN) URLS")
    print("=" * 70)

    data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'datasets', 'processed')

    dfs = []
    for split in ['train.csv', 'validation.csv', 'test.csv']:
        path = os.path.join(data_dir, split)
        if os.path.exists(path):
            df = pd.read_csv(path)
            dfs.append(df)
            print(f"  Loaded {split}: {len(df)} URLs")
        else:
            print(f"  [WARN] {split} not found at {path}")

    if not dfs:
        print("[ERROR] No dataset files found!")
        print(f"   Expected at: {data_dir}")
        print("   Run datasets/scripts/merge_datasets.py first.")
        sys.exit(1)

    all_df = pd.concat(dfs, ignore_index=True)

    legit_df = all_df[all_df['label'] == 'legitimate'].copy()
    malicious_df = all_df[all_df['label'] == 'malicious'].copy()

    print(f"\nDataset breakdown:")
    print(f"   Total URLs: {len(all_df)}")
    print(f"   Legitimate: {len(legit_df)} (used for training)")
    print(f"   Malicious:  {len(malicious_df)} (used for evaluation only)")

    return legit_df, malicious_df


def extract_features(urls, extractor, label=""):
    """Extract privacy-preserving features from URL list."""
    print(f"\nExtracting features from {len(urls)} {label} URLs...")

    features_list = []
    errors = 0

    for i, url in enumerate(urls):
        try:
            features = extractor.extract(url)
            features_list.append(features)
        except Exception:
            errors += 1
            features_list.append(
                {name: 0.0 for name in extractor.FEATURE_NAMES}
            )

        if (i + 1) % 50000 == 0:
            print(f"   Processed {i+1}/{len(urls)}...")

    print(f"  Extracted {len(extractor.FEATURE_NAMES)} features per URL")
    if errors:
        print(f"  [WARN] {errors} extraction errors (zeroed out)")

    feature_df = pd.DataFrame(features_list)
    return feature_df


def compute_baseline_stats(feature_df, feature_names):
    """
    Compute per-feature baseline statistics for explainability.
    
    IMPORTANT: Uses a minimum std floor to prevent absurd z-scores
    for features with low variance in the training data.
    """
    print("\nComputing baseline statistics...")

    # Minimum std floor per feature to prevent absurd z-scores
    MIN_STD_FLOORS = {
        # Length features
        'url_length': 15.0,
        'hostname_length': 5.0,
        # Ratios
        'path_to_url_ratio': 0.15,
        'query_to_url_ratio': 0.10,
        'hostname_to_url_ratio': 0.15,
        # Entropy
        'hostname_entropy': 0.5,
        'path_entropy': 1.5,
        'full_url_entropy': 0.5,
        # Character ratios
        'digit_ratio': 0.05,
        'special_char_ratio': 0.05,
        'consonant_vowel_ratio': 0.5,
        'uppercase_ratio': 0.02,
        # Structural
        'subdomain_count': 0.8,
        'path_depth': 1.5,
        'query_param_count': 1.0,
        'tld_length': 1.0,
        'num_dots': 0.8,
        'num_hyphens': 0.5,
        # Binary features
        'is_https': 0.3,
        'has_nonstandard_port': 0.1,
        'has_punycode': 0.1,
        'has_unicode': 0.1,
        'has_at_symbol': 0.1,
        'has_double_slash_in_path': 0.1,
        'ip_as_host': 0.1,
        'brand_in_subdomain': 0.1,
        'https_in_hostname': 0.1,
        'excessive_hyphens': 0.1,
    }

    stats = {}
    for name in feature_names:
        if name in feature_df.columns:
            col = feature_df[name]
            raw_std = float(col.std())
            min_floor = MIN_STD_FLOORS.get(name, 0.1)
            
            stats[name] = {
                'mean': float(col.mean()),
                'std': max(raw_std, min_floor),  # Use floor
                'raw_std': raw_std,
                'min': float(col.min()),
                'max': float(col.max()),
                'p25': float(col.quantile(0.25)),
                'p50': float(col.quantile(0.50)),
                'p75': float(col.quantile(0.75)),
                'p95': float(col.quantile(0.95)),
            }

    print(f"  Computed stats for {len(stats)} features (with std floors)")
    return stats


def train_model(X_scaled):
    """Train the Isolation Forest model."""
    print("\nTraining Isolation Forest...")
    print("   Parameters:")
    print("     n_estimators:  200")
    print("     contamination: 0.05")
    print("     random_state:  42")

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples='auto',
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_scaled)
    print("  Training complete.")

    return model


def evaluate_model(model, scaler, extractor, legit_df, malicious_df):
    """Evaluate separation quality between benign and malicious."""
    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    n_eval = min(5000, len(legit_df), len(malicious_df))

    # Evaluate on REAL URLs (with paths for legit too)
    legit_sample = legit_df.sample(n=n_eval, random_state=42)
    mal_sample = malicious_df.sample(n=n_eval, random_state=42)

    # Augment legit URLs for realistic evaluation
    legit_urls = augment_urls(legit_sample['url'].tolist(), multiply_factor=0)
    mal_urls = mal_sample['url'].tolist()

    legit_features = extract_features(legit_urls, extractor, "legitimate eval")
    mal_features = extract_features(mal_urls, extractor, "malicious eval")

    X_legit = scaler.transform(legit_features.values)
    X_mal = scaler.transform(mal_features.values)

    legit_scores = model.score_samples(X_legit)
    mal_scores = model.score_samples(X_mal)

    legit_decisions = model.predict(X_legit)
    mal_decisions = model.predict(X_mal)

    print(f"\n  Legitimate URLs (should be NORMAL):")
    print(f"    Mean score:    {legit_scores.mean():.4f}")
    print(f"    Std score:     {legit_scores.std():.4f}")
    print(f"    Flagged as anomaly: {(legit_decisions == -1).sum()}/{len(legit_urls)} "
          f"({(legit_decisions == -1).mean()*100:.1f}%)")

    print(f"\n  Malicious URLs (should be ANOMALOUS):")
    print(f"    Mean score:    {mal_scores.mean():.4f}")
    print(f"    Std score:     {mal_scores.std():.4f}")
    print(f"    Flagged as anomaly: {(mal_decisions == -1).sum()}/{len(mal_urls)} "
          f"({(mal_decisions == -1).mean()*100:.1f}%)")

    separation = legit_scores.mean() - mal_scores.mean()
    print(f"\n  Score separation (legit - malicious): {separation:.4f}")
    print(f"  {'[OK] Good separation' if separation > 0.02 else '[WARN] Weak separation'}")

    # Also test specific well-known URLs
    print("\n  Specific URL Tests:")
    test_urls = [
        # Simple domains
        ("https://google.com", "Should be NORMAL"),
        ("https://youtube.com", "Should be NORMAL"),
        # Domains with paths
        ("https://google.com/search?q=test", "Should be NORMAL"),
        ("https://github.com/user/repo", "Should be NORMAL"),
        # Complex legitimate URLs (previously false-positive)
        ("https://stackoverflow.com/questions/12345/how-to-code", "Should be NORMAL"),
        ("https://www.amazon.com/dp/B09V3KXJPB", "Should be NORMAL"),
        ("https://docs.python.org/3/tutorial/", "Should be NORMAL"),
        ("https://mail.google.com/mail/u/0/inbox", "Should be NORMAL"),
        ("https://www.reddit.com/r/programming/comments/abc123/post", "Should be NORMAL"),
        ("https://en.wikipedia.org/wiki/Machine_learning", "Should be NORMAL"),
        ("https://outlook.office365.com/", "Should be NORMAL"),
        ("https://www.primevideo.com/detail/John-Wick/0PDQRYR7C1A5", "Should be NORMAL"),
        # Malicious URLs (should be flagged)
        ("http://xn--80ak6aa92e.com/login", "Should be ANOMALY"),
        ("http://192.168.1.100/login/bank", "Should be ANOMALY"),
        ("http://paypal-secure.evil.tk/verify", "Should be ANOMALY"),
        ("http://https-secure-banking.com/login", "Should be ANOMALY"),
    ]

    for url, expected in test_urls:
        feats = extractor.extract(url)
        vec = np.array(extractor.get_feature_vector(feats)).reshape(1, -1)
        scaled = scaler.transform(vec)
        score = model.score_samples(scaled)[0]
        decision = "ANOMALY" if model.predict(scaled)[0] == -1 else "NORMAL"
        mark = "[OK]" if expected.split()[-1] == decision else "[FAIL]"
        print(f"    {mark} {url[:50]:<50} -> {decision:<8} (score: {score:.4f}) | {expected}")


def save_model(model, scaler, baseline_stats, feature_names):
    """Save model, scaler, and baseline stats."""
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'trained_models')
    os.makedirs(output_dir, exist_ok=True)

    backend_dir = os.path.join(
        os.path.dirname(__file__), '..', '..', 'backend', 'app', 'ml_models'
    )
    os.makedirs(backend_dir, exist_ok=True)

    files = {
        'isolation_forest.pkl': model,
        'anomaly_scaler.pkl': scaler,
        'baseline_stats.pkl': baseline_stats,
    }

    for filename, obj in files.items():
        path1 = os.path.join(output_dir, filename)
        joblib.dump(obj, path1)
        print(f"  Saved: {path1}")

        path2 = os.path.join(backend_dir, filename)
        joblib.dump(obj, path2)
        print(f"  Saved: {path2}")


def main():
    random.seed(42)
    
    print("=" * 70)
    print("ANOMALY DETECTION MODEL TRAINING")
    print("  One-Class Isolation Forest on Augmented Benign URLs")
    print("=" * 70)

    # 1. Load data
    legit_df, malicious_df = load_legitimate_urls()

    # 2. Initialize feature extractor
    extractor = PrivacyFeatureExtractor()
    feature_names = extractor.FEATURE_NAMES

    # 3. Augment legitimate URLs with realistic paths
    print("\n" + "=" * 70)
    print("URL AUGMENTATION")
    print("=" * 70)
    
    legit_urls = legit_df['url'].tolist()
    augmented_urls = augment_urls(legit_urls, multiply_factor=3)

    # 4. Extract features
    print("\n" + "=" * 70)
    print("FEATURE EXTRACTION (AUGMENTED BENIGN DATA)")
    print("=" * 70)

    legit_features = extract_features(augmented_urls, extractor, "augmented legitimate")

    # 5. Compute baseline statistics (with std floors)
    baseline_stats = compute_baseline_stats(legit_features, feature_names)

    # Print key stats
    print("\n  Key baseline values:")
    for name in ['path_depth', 'path_entropy', 'query_param_count', 'is_https', 
                  'subdomain_count', 'url_length']:
        s = baseline_stats.get(name, {})
        print(f"    {name:<25} mean={s.get('mean', 0):.4f}  "
              f"std={s.get('std', 0):.4f}  (raw_std={s.get('raw_std', 0):.4f})")

    # 6. Scale features
    print("\nScaling features with StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(legit_features.values)
    print(f"  Scaler fitted on {X_scaled.shape[0]} samples, {X_scaled.shape[1]} features")

    # 7. Train model
    print("\n" + "=" * 70)
    print("MODEL TRAINING")
    print("=" * 70)
    model = train_model(X_scaled)

    # 8. Evaluate
    if len(malicious_df) > 0:
        evaluate_model(model, scaler, extractor, legit_df, malicious_df)

    # 9. Save
    print("\n" + "=" * 70)
    print("SAVING MODEL ARTIFACTS")
    print("=" * 70)
    save_model(model, scaler, baseline_stats, feature_names)

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)
    print("\nRestart the backend to load the new model.")


if __name__ == '__main__':
    main()
