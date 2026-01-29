"""
Train XGBoost model for malicious URL detection
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import xgboost as xgb
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from feature_extractor import URLFeatureExtractor
import os

def load_data(filepath):
    """Load dataset"""
    print(f"📖 Loading data from {filepath}...")
    df = pd.read_csv(filepath)
    print(f"✅ Loaded {len(df)} URLs")
    print(f"   - Malicious: {len(df[df['label'] == 'malicious'])}")
    print(f"   - Legitimate: {len(df[df['label'] == 'legitimate'])}")
    return df

def extract_features_from_dataset(df, extractor):
    """Extract features from all URLs in dataset"""
    print("\n🔧 Extracting features from URLs...")
    
    features_df = extractor.extract_features_batch(df['url'].tolist())
    
    # Add label (convert to binary: 1 = malicious, 0 = legitimate)
    features_df['label'] = (df['label'] == 'malicious').astype(int)
    
    print(f"✅ Extracted {len(features_df.columns) - 1} features")
    
    return features_df

def train_model(X_train, y_train, X_val, y_val):
    """Train XGBoost model"""
    print("\n🤖 Training XGBoost model...")
    
    # XGBoost parameters
    params = {
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'random_state': 42,
        'n_jobs': -1
    }
    
    # Create model
    model = xgb.XGBClassifier(**params)
    
    # Train with early stopping
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    print("✅ Training complete!")
    
    return model

def evaluate_model(model, X, y, dataset_name="Test"):
    """Evaluate model performance"""
    print(f"\n📊 Evaluating on {dataset_name} set...")
    
    # Predictions
    y_pred = model.predict(X)
    y_pred_proba = model.predict_proba(X)[:, 1]
    
    # Metrics
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred)
    recall = recall_score(y, y_pred)
    f1 = f1_score(y, y_pred)
    
    print(f"\n{'='*60}")
    print(f"{dataset_name.upper()} SET RESULTS")
    print(f"{'='*60}")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f}")
    print(f"{'='*60}")
    
    # Confusion Matrix
    cm = confusion_matrix(y, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Legit  Malicious")
    print(f"Actual Legit     {cm[0][0]:<6} {cm[0][1]:<6}")
    print(f"       Malicious {cm[1][0]:<6} {cm[1][1]:<6}")
    
    # Classification Report
    print(f"\nDetailed Classification Report:")
    print(classification_report(y, y_pred, target_names=['Legitimate', 'Malicious']))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm
    }

def save_model(model, feature_names, output_dir='../trained_models'):
    """Save trained model"""
    os.makedirs(output_dir, exist_ok=True)
    
    model_path = os.path.join(output_dir, 'xgboost_model.pkl')
    features_path = os.path.join(output_dir, 'feature_names.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(feature_names, features_path)
    
    print(f"\n💾 Model saved to: {model_path}")
    print(f"💾 Feature names saved to: {features_path}")

def plot_feature_importance(model, feature_names, top_n=20):
    """Plot feature importance"""
    print(f"\n📊 Plotting top {top_n} important features...")
    
    # Get feature importance
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1][:top_n]
    
    plt.figure(figsize=(10, 8))
    plt.title(f'Top {top_n} Most Important Features')
    plt.barh(range(top_n), importance[indices])
    plt.yticks(range(top_n), [feature_names[i] for i in indices])
    plt.xlabel('Importance')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    
    os.makedirs('../evaluation', exist_ok=True)
    plt.savefig('../evaluation/feature_importance.png', dpi=300, bbox_inches='tight')
    print("💾 Saved to: ../evaluation/feature_importance.png")
    
    # Print top features
    print(f"\nTop {min(10, top_n)} Features:")
    for i in range(min(10, top_n)):
        idx = indices[i]
        print(f"  {i+1}. {feature_names[idx]:<30} {importance[idx]:.4f}")

def main():
    print("=" * 60)
    print("🎓 MALICIOUS URL DETECTION - MODEL TRAINING")
    print("=" * 60)
    
    # Load data
    train_df = load_data('../../datasets/processed/train.csv')
    val_df = load_data('../../datasets/processed/validation.csv')
    test_df = load_data('../../datasets/processed/test.csv')
    
    # Initialize feature extractor
    extractor = URLFeatureExtractor()
    
    # Extract features
    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION")
    print("=" * 60)
    
    train_features = extract_features_from_dataset(train_df, extractor)
    val_features = extract_features_from_dataset(val_df, extractor)
    test_features = extract_features_from_dataset(test_df, extractor)
    
    # Prepare data
    feature_columns = [col for col in train_features.columns if col != 'label']
    
    X_train = train_features[feature_columns]
    y_train = train_features['label']
    
    X_val = val_features[feature_columns]
    y_val = val_features['label']
    
    X_test = test_features[feature_columns]
    y_test = test_features['label']
    
    print(f"\nDataset shapes:")
    print(f"  Train: {X_train.shape}")
    print(f"  Val:   {X_val.shape}")
    print(f"  Test:  {X_test.shape}")
    
    # Train model
    print("\n" + "=" * 60)
    print("MODEL TRAINING")
    print("=" * 60)
    
    model = train_model(X_train, y_train, X_val, y_val)
    
    # Evaluate
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    train_metrics = evaluate_model(model, X_train, y_train, "Training")
    val_metrics = evaluate_model(model, X_val, y_val, "Validation")
    test_metrics = evaluate_model(model, X_test, y_test, "Test")
    
    # Feature importance
    plot_feature_importance(model, feature_columns)
    
    # Save model
    save_model(model, feature_columns)
    
    # Save metrics
    metrics_summary = {
        'train': train_metrics,
        'validation': val_metrics,
        'test': test_metrics
    }
    
    os.makedirs('../evaluation', exist_ok=True)
    joblib.dump(metrics_summary, '../evaluation/model_metrics.pkl')
    
    print("\n" + "=" * 60)
    print("✅ TRAINING COMPLETE!")
    print("=" * 60)
    print("\nFiles created:")
    print("  📁 ../trained_models/xgboost_model.pkl")
    print("  📁 ../trained_models/feature_names.pkl")
    print("  📁 ../evaluation/feature_importance.png")
    print("  📁 ../evaluation/model_metrics.pkl")

if __name__ == '__main__':
    main()