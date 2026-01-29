"""
Improved XGBoost Training with Better Features
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import xgboost as xgb
import joblib
import matplotlib.pyplot as plt
from feature_extractor_v2 import URLFeatureExtractorV2
import os

def load_and_balance_data():
    """Load and balance dataset"""
    print("=" * 70)
    print("📊 LOADING AND BALANCING DATA")
    print("=" * 70)
    
    # Load all splits
    train_df = pd.read_csv('../../datasets/processed/train.csv')
    val_df = pd.read_csv('../../datasets/processed/validation.csv')
    test_df = pd.read_csv('../../datasets/processed/test.csv')
    
    # Combine for reprocessing
    all_df = pd.concat([train_df, val_df, test_df], ignore_index=True)
    
    print(f"✅ Total URLs loaded: {len(all_df)}")
    print(f"   Malicious: {len(all_df[all_df['label'] == 'malicious'])}")
    print(f"   Legitimate: {len(all_df[all_df['label'] == 'legitimate'])}")
    
    return all_df

def extract_improved_features(df, extractor):
    """Extract features using improved extractor"""
    print("\n🔧 Extracting improved features...")
    
    features_df = extractor.extract_features_batch(df['url'].tolist())
    features_df['label'] = (df['label'] == 'malicious').astype(int)
    
    print(f"✅ Extracted {len(features_df.columns) - 1} features")
    print(f"   Feature count increased from 38 to {len(features_df.columns) - 1}")
    
    return features_df

def train_improved_model(X_train, y_train, X_val, y_val):
    """Train XGBoost with improved parameters"""
    print("\n🤖 Training improved XGBoost model...")
    
    # Improved parameters (FIXED: removed early_stopping_rounds from params)
    params = {
        'max_depth': 7,
        'learning_rate': 0.05,
        'n_estimators': 300,
        'min_child_weight': 3,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'random_state': 42,
        'n_jobs': -1,
        'scale_pos_weight': 1,
        'early_stopping_rounds': 20  # MOVED HERE
    }
    
    model = xgb.XGBClassifier(**params)
    
    # Train (FIXED: removed early_stopping_rounds from fit())
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    print(f"✅ Training complete!")
    
    return model

def cross_validate_model(X, y, feature_names):
    """Perform cross-validation to check generalization"""
    print("\n🔄 Performing 5-fold cross-validation...")
    
    params = {
        'max_depth': 7,
        'learning_rate': 0.05,
        'n_estimators': 300,
        'min_child_weight': 3,
        'random_state': 42
    }
    
    model = xgb.XGBClassifier(**params)
    
    # Stratified K-Fold
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    # Cross-validation scores
    cv_scores = cross_val_score(model, X, y, cv=skf, scoring='accuracy', n_jobs=-1)
    
    print(f"\n📊 Cross-Validation Results:")
    print(f"   Accuracy scores: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"   Mean accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    return cv_scores

def evaluate_model(model, X, y, dataset_name="Test"):
    """Evaluate model with detailed metrics"""
    print(f"\n📊 Evaluating on {dataset_name} set...")
    
    y_pred = model.predict(X)
    y_pred_proba = model.predict_proba(X)[:, 1]
    
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred)
    recall = recall_score(y, y_pred)
    f1 = f1_score(y, y_pred)
    
    print(f"\n{'='*70}")
    print(f"{dataset_name.upper()} SET RESULTS")
    print(f"{'='*70}")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f}")
    print(f"{'='*70}")
    
    cm = confusion_matrix(y, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Legit  Malicious")
    print(f"Actual Legit     {cm[0][0]:<6} {cm[0][1]:<6}")
    print(f"       Malicious {cm[1][0]:<6} {cm[1][1]:<6}")
    
    # False positive and false negative rates
    fpr = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    fnr = cm[1][0] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
    
    print(f"\nError Analysis:")
    print(f"  False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  False Negative Rate: {fnr:.4f} ({fnr*100:.2f}%)")
    
    print(f"\nDetailed Classification Report:")
    print(classification_report(y, y_pred, target_names=['Legitimate', 'Malicious']))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm,
        'fpr': fpr,
        'fnr': fnr
    }

def save_improved_model(model, feature_names, output_dir='../trained_models'):
    """Save the improved model"""
    os.makedirs(output_dir, exist_ok=True)
    
    model_path = os.path.join(output_dir, 'xgboost_model_v2.pkl')
    features_path = os.path.join(output_dir, 'feature_names_v2.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(feature_names, features_path)
    
    print(f"\n💾 Improved model saved:")
    print(f"   {model_path}")
    print(f"   {features_path}")

def plot_feature_importance(model, feature_names, top_n=20):
    """Plot feature importance"""
    print(f"\n📊 Plotting top {top_n} important features...")
    
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1][:top_n]
    
    plt.figure(figsize=(10, 8))
    plt.title(f'Top {top_n} Most Important Features (V2)')
    plt.barh(range(top_n), importance[indices])
    plt.yticks(range(top_n), [feature_names[i] for i in indices])
    plt.xlabel('Importance')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    
    os.makedirs('../evaluation', exist_ok=True)
    plt.savefig('../evaluation/feature_importance_v2.png', dpi=300, bbox_inches='tight')
    print("💾 Saved to: ../evaluation/feature_importance_v2.png")
    
    print(f"\nTop 10 Features:")
    for i in range(min(10, top_n)):
        idx = indices[i]
        print(f"  {i+1}. {feature_names[idx]:<35} {importance[idx]:.4f}")

def main():
    print("=" * 70)
    print("🎓 IMPROVED MALICIOUS URL DETECTION - MODEL TRAINING V2")
    print("=" * 70)
    
    # Load data
    all_df = load_and_balance_data()
    
    # Initialize improved extractor
    extractor = URLFeatureExtractorV2()
    
    # Extract features
    print("\n" + "=" * 70)
    print("IMPROVED FEATURE EXTRACTION")
    print("=" * 70)
    
    features_df = extract_improved_features(all_df, extractor)
    
    # Split data
    feature_columns = [col for col in features_df.columns if col != 'label']
    X = features_df[feature_columns]
    y = features_df['label']
    
    # Train/Val/Test split (70/15/15)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp
    )
    
    print(f"\nDataset shapes:")
    print(f"  Train: {X_train.shape}")
    print(f"  Val:   {X_val.shape}")
    print(f"  Test:  {X_test.shape}")
    
    # Cross-validation
    cv_scores = cross_validate_model(X_train, y_train, feature_columns)
    
    # Train model
    print("\n" + "=" * 70)
    print("MODEL TRAINING")
    print("=" * 70)
    
    model = train_improved_model(X_train, y_train, X_val, y_val)
    
    # Evaluate
    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)
    
    train_metrics = evaluate_model(model, X_train, y_train, "Training")
    val_metrics = evaluate_model(model, X_val, y_val, "Validation")
    test_metrics = evaluate_model(model, X_test, y_test, "Test")
    
    # Feature importance
    plot_feature_importance(model, feature_columns)
    
    # Save model
    save_improved_model(model, feature_columns)
    
    # Save metrics
    metrics_summary = {
        'train': train_metrics,
        'validation': val_metrics,
        'test': test_metrics,
        'cross_validation_scores': cv_scores.tolist(),
        'feature_count': len(feature_columns)
    }
    
    os.makedirs('../evaluation', exist_ok=True)
    joblib.dump(metrics_summary, '../evaluation/model_metrics_v2.pkl')
    
    print("\n" + "=" * 70)
    print("✅ IMPROVED TRAINING COMPLETE!")
    print("=" * 70)
    print("\nFiles created:")
    print("  📁 ../trained_models/xgboost_model_v2.pkl")
    print("  📁 ../trained_models/feature_names_v2.pkl")
    print("  📁 ../evaluation/feature_importance_v2.png")
    print("  📁 ../evaluation/model_metrics_v2.pkl")

if __name__ == '__main__':
    main()
