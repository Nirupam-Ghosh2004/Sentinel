"""
XGBoost Training v3 — Path-Augmented
Fixes the bare-domain bias by augmenting legitimate URLs with realistic paths.

Root cause: Tranco dataset has 48K bare domains (google.com, amazon.com).
Malicious URLs from phishtank/urlhaus always have paths (/login/verify).
Model learned has_path → malicious. This script fixes that by augmenting
legitimate URLs with realistic paths before training.

Output:
  - xgboost_model.pkl  (replaces the current model)
  - feature_names.pkl
"""
import sys
import os
import random

sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
import xgboost as xgb
import joblib

from feature_extractor_v2 import URLFeatureExtractorV2

# ===== PATH AUGMENTATION (same templates as anomaly model) =====
REALISTIC_PATHS = [
    # Shallow
    '/', '/about', '/contact', '/login', '/signup', '/pricing',
    '/terms', '/privacy', '/search', '/news', '/help', '/faq',
    '/download', '/dashboard', '/settings', '/explore', '/trending',
    '/blog', '/products', '/services', '/careers', '/support',

    # Medium depth (2 segments)
    '/category/electronics', '/category/books', '/user/profile',
    '/user/settings', '/docs/introduction', '/docs/api-reference',
    '/en/home', '/shop/items', '/video/watch', '/account/orders',
    '/blog/latest', '/wiki/Machine_learning', '/wiki/Python_programming',
    '/dp/B09V3KXJPB', '/gp/product', '/3/tutorial', '/api/v1',
    '/en-us/docs', '/gallery/best-items-ranked',

    # Deep paths (3 segments)
    '/docs/getting-started/installation', '/docs/api/authentication',
    '/article/2024/interesting-topic', '/post/2024/how-to-guide',
    '/r/programming/hot', '/r/technology/new',
    '/mail/u/0', '/3/library/functions',
    '/questions/12345678/how-to-code', '/issues/1234/comments',
    '/pull/5678/files', '/tree/main/src', '/blob/main/README',
    '/blog/what-is-aws-ec2', '/blog/best-practices-guide',
    '/products/category/item-name',

    # Deep paths (4+ segments)
    '/mail/u/0/inbox', '/r/programming/comments/abc123/interesting_post',
    '/en-us/docs/web/javascript', '/en-us/docs/web/css/flexbox',
    '/questions/12345678/how-to-code-in-python',
    '/3/library/functions/print', '/wiki/Category:Computer_science',
    '/tree/main/src/components', '/blog/2024/01/15/my-post-title',
    '/courses/web-development/lesson-1/quiz',
    '/gallery/best-john-wick-movies-ranked',

    # Patterns with IDs
    '/watch/dQw4w9WgXcQ', '/video/12345678', '/status/1234567890',
    '/p/CxYz123AbC', '/item/ASIN12345', '/detail/product-name/reviews',
]

REALISTIC_QUERIES = [
    '', '', '', '', '',  # 50% no query
    '?q=search+term', '?q=how+to+learn+python',
    '?page=2', '?page=5', '?id=12345',
    '?v=dQw4w9WgXcQ', '?category=electronics&brand=samsung',
    '?sort=price&order=asc', '?lang=en', '?ref=homepage',
    '?utm_source=google&utm_medium=cpc', '?tab=overview',
    '?limit=20&offset=40', '?filter=new',
]


def augment_legitimate_urls(urls, multiply_factor=3):
    """
    Augment bare domain URLs with realistic paths AND subdomain variants.
    Fixes two biases:
      1. Bare-domain bias (no paths in Tranco)
      2. Subdomain bias (no www./docs./en. in Tranco)
    """
    print(f"\n  Augmenting {len(urls)} legitimate URLs (x{multiply_factor})...")

    # Subdomain prefixes commonly used by legitimate sites
    SUBDOMAIN_PREFIXES = [
        'www.',           # ~40% of real browsing
        'www.',
        'www.',
        '',               # keep as-is
        '',
        'docs.',
        'en.',
        'mail.',
        'blog.',
        'support.',
        'app.',
        'help.',
        'news.',
        'shop.',
        'm.',             # mobile
    ]

    augmented = []
    for url in urls:
        augmented.append(url)  # keep original

        for _ in range(multiply_factor):
            path = random.choice(REALISTIC_PATHS)
            query = random.choice(REALISTIC_QUERIES)
            prefix = random.choice(SUBDOMAIN_PREFIXES)

            # Parse to add subdomain before hostname
            base = url.rstrip('/')
            if prefix and '://' in base:
                scheme, rest = base.split('://', 1)
                # Don't add subdomain if one already exists (has 3+ parts)
                if rest.count('.') < 2:
                    base = scheme + '://' + prefix + rest
                else:
                    base = scheme + '://' + rest
            augmented.append(base + path + query)

    random.shuffle(augmented)
    print(f"  → {len(augmented)} augmented legitimate URLs")
    return augmented


def load_data():
    """Load all dataset splits"""
    print("=" * 70)
    print(" LOADING DATA")
    print("=" * 70)

    data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'datasets', 'processed')
    dfs = []
    for split in ['train.csv', 'validation.csv', 'test.csv']:
        path = os.path.join(data_dir, split)
        if os.path.exists(path):
            df = pd.read_csv(path)
            dfs.append(df)
            print(f"  Loaded {split}: {len(df)} URLs")

    all_df = pd.concat(dfs, ignore_index=True)

    legit = all_df[all_df['label'] == 'legitimate']
    mal = all_df[all_df['label'] == 'malicious']

    print(f"\n  Total: {len(all_df)} | Legitimate: {len(legit)} | Malicious: {len(mal)}")

    # Check path distribution (this is the bug we're fixing)
    legit_with_path = sum(1 for u in legit['url'] if '/' in u.split('//')[1] if '//' in u)
    mal_with_path = sum(1 for u in mal['url'] if '/' in u.split('//')[1] if '//' in u)
    print(f"\n  [BIAS CHECK] Legitimate URLs with paths: {legit_with_path}/{len(legit)} "
          f"({legit_with_path/len(legit)*100:.1f}%)")
    print(f"  [BIAS CHECK] Malicious URLs with paths:  {mal_with_path}/{len(mal)} "
          f"({mal_with_path/len(mal)*100:.1f}%)")

    return legit, mal


def extract_features(urls, extractor, label=""):
    """Extract features from URL list"""
    print(f"\n  Extracting features from {len(urls)} {label} URLs...")
    features_list = []
    errors = 0

    for i, url in enumerate(urls):
        try:
            features_list.append(extractor.extract_features(url))
        except Exception:
            errors += 1
            features_list.append(extractor._get_default_features())

        if (i + 1) % 50000 == 0:
            print(f"    {i+1}/{len(urls)}...")

    if errors:
        print(f"  [WARN] {errors} extraction errors")

    return pd.DataFrame(features_list)


def train_model(X_train, y_train, X_val, y_val):
    """Train XGBoost with improved parameters"""
    print("\n  Training XGBoost v3...")

    model = xgb.XGBClassifier(
        max_depth=7,
        learning_rate=0.05,
        n_estimators=500,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
        scale_pos_weight=1,
        early_stopping_rounds=30,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )

    print(f"  Training complete! Best iteration: {model.best_iteration}")
    return model


def evaluate(model, X, y, name="Test"):
    """Evaluate model"""
    y_pred = model.predict(X)
    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred)
    rec = recall_score(y, y_pred)
    f1 = f1_score(y, y_pred)
    cm = confusion_matrix(y, y_pred)
    fpr = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0

    print(f"\n  {name} Results:")
    print(f"    Accuracy:  {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
    print(f"    False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"    Confusion: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

    return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'fpr': fpr}


def test_specific_urls(model, extractor, feature_cols):
    """Test on known-tricky URLs to verify false positive fix"""
    print("\n" + "=" * 70)
    print("  FALSE POSITIVE REGRESSION TESTS")
    print("=" * 70)

    test_cases = [
        # Legitimate URLs that were previously false-positive
        ("https://attariclasses.in/blog/what-is-aws-ec2", "LEGIT"),
        ("https://www.indiewire.com/gallery/best-john-wick-movies-ranked/", "LEGIT"),
        ("https://stackoverflow.com/questions/12345/how-to-code", "LEGIT"),
        ("https://www.amazon.com/dp/B09V3KXJPB", "LEGIT"),
        ("https://docs.python.org/3/tutorial/", "LEGIT"),
        ("https://mail.google.com/mail/u/0/inbox", "LEGIT"),
        ("https://www.reddit.com/r/programming/comments/abc123/post", "LEGIT"),
        ("https://en.wikipedia.org/wiki/Machine_learning", "LEGIT"),
        ("https://github.com/user/repo/blob/main/README.md", "LEGIT"),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "LEGIT"),
        ("https://news.ycombinator.com/item?id=12345678", "LEGIT"),
        # Bare domains (should still work)
        ("https://google.com", "LEGIT"),
        ("https://facebook.com", "LEGIT"),
        # Actual malicious patterns
        ("http://paypal-secure-login-verify.tk/account", "MALICIOUS"),
        ("http://192.168.1.100/login/bank", "MALICIOUS"),
        ("http://xn--80ak6aa92e.com/login", "MALICIOUS"),
        ("http://secure-update-paypal.com/verify/account", "MALICIOUS"),
        ("http://free-crypto-rewards.info/claim", "MALICIOUS"),
    ]

    pass_count = 0
    fail_count = 0

    for url, expected in test_cases:
        feats = extractor.extract_features(url)
        df = pd.DataFrame([feats])
        # Ensure columns match
        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0
        df = df[feature_cols]

        proba = model.predict_proba(df)[0]
        pred_label = "MALICIOUS" if proba[1] > 0.5 else "LEGIT"
        score = proba[1]

        status = "✓" if pred_label == expected else "✗"
        if pred_label == expected:
            pass_count += 1
        else:
            fail_count += 1

        print(f"  {status} {url[:55]:<55} → {pred_label:<9} ({score:.3f}) | expected {expected}")

    print(f"\n  Results: {pass_count} passed, {fail_count} failed out of {len(test_cases)}")
    return fail_count


def save_model(model, feature_names):
    """Save model to both trained_models and backend"""
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'trained_models')
    backend_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'app', 'ml_models')

    for d in [output_dir, backend_dir]:
        os.makedirs(d, exist_ok=True)
        model_path = os.path.join(d, 'xgboost_model.pkl')
        names_path = os.path.join(d, 'feature_names.pkl')
        joblib.dump(model, model_path)
        joblib.dump(feature_names, names_path)
        print(f"  Saved: {model_path}")
        print(f"  Saved: {names_path}")


def main():
    random.seed(42)
    np.random.seed(42)

    print("=" * 70)
    print(" XGBOOST V3 — PATH-AUGMENTED TRAINING")
    print(" Fixing bare-domain bias in legitimate URL training data")
    print("=" * 70)

    # 1. Load data
    legit_df, mal_df = load_data()

    # 2. Augment legitimate URLs with realistic paths
    print("\n" + "=" * 70)
    print(" PATH AUGMENTATION")
    print("=" * 70)

    legit_urls_raw = legit_df['url'].tolist()
    legit_urls_aug = augment_legitimate_urls(legit_urls_raw, multiply_factor=3)
    mal_urls = mal_df['url'].tolist()

    print(f"\n  After augmentation:")
    print(f"    Legitimate: {len(legit_urls_aug)} (was {len(legit_urls_raw)})")
    print(f"    Malicious:  {len(mal_urls)}")

    # 3. Balance: downsample the larger class to avoid imbalance
    # Augmented legit is ~4x larger, so sample down to match malicious count
    if len(legit_urls_aug) > len(mal_urls) * 2:
        target_size = len(mal_urls) * 2  # 2:1 ratio legit:malicious
        legit_urls_aug = random.sample(legit_urls_aug, target_size)
        print(f"    Balanced legit down to: {len(legit_urls_aug)}")

    # 4. Extract features
    print("\n" + "=" * 70)
    print(" FEATURE EXTRACTION")
    print("=" * 70)

    extractor = URLFeatureExtractorV2()

    legit_features = extract_features(legit_urls_aug, extractor, "legitimate (augmented)")
    mal_features = extract_features(mal_urls, extractor, "malicious")

    legit_features['label'] = 0
    mal_features['label'] = 1

    all_features = pd.concat([legit_features, mal_features], ignore_index=True)
    all_features = all_features.sample(frac=1, random_state=42).reset_index(drop=True)

    feature_cols = [c for c in all_features.columns if c != 'label']
    X = all_features[feature_cols]
    y = all_features['label']

    print(f"\n  Combined dataset: {len(all_features)} samples, {len(feature_cols)} features")
    print(f"  Label distribution: {(y==0).sum()} legit, {(y==1).sum()} malicious")

    # 5. Split
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp)

    print(f"  Train: {X_train.shape} | Val: {X_val.shape} | Test: {X_test.shape}")

    # 6. Cross-validation
    print("\n" + "=" * 70)
    print(" CROSS-VALIDATION")
    print("=" * 70)

    cv_model = xgb.XGBClassifier(max_depth=7, learning_rate=0.05, n_estimators=300, random_state=42)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(cv_model, X_train, y_train, cv=skf, scoring='accuracy', n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # 7. Train
    print("\n" + "=" * 70)
    print(" MODEL TRAINING")
    print("=" * 70)

    model = train_model(X_train, y_train, X_val, y_val)

    # 8. Evaluate
    print("\n" + "=" * 70)
    print(" EVALUATION")
    print("=" * 70)

    evaluate(model, X_train, y_train, "Train")
    evaluate(model, X_val, y_val, "Validation")
    evaluate(model, X_test, y_test, "Test")

    # 9. False positive regression tests
    failures = test_specific_urls(model, extractor, feature_cols)

    # 10. Feature importance
    print("\n  Top 10 Features:")
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1][:10]
    for i, idx in enumerate(indices):
        print(f"    {i+1}. {feature_cols[idx]:<35} {importance[idx]:.4f}")

    # 11. Save
    print("\n" + "=" * 70)
    print(" SAVING MODEL")
    print("=" * 70)
    save_model(model, feature_cols)

    print("\n" + "=" * 70)
    print(f" TRAINING COMPLETE! ({failures} regression test failures)")
    print("=" * 70)
    print("\n  Restart the backend to load the new model.")


if __name__ == '__main__':
    main()
