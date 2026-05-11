import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
from pathlib import Path
from ml.features import extract_features, feature_cols

def main():
    BASE_DIR = Path(__file__).parent
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'

    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    if 'url' not in df.columns:
        raise ValueError("CSV must contain 'url' column")

    print(f"Original size: {len(df)}")
    print("Re‑extracting features (this may take a few minutes)...")

    new_features = []
    for i, url in enumerate(df['url']):
        if (i+1) % 50000 == 0:
            print(f"Processed {i+1}/{len(df)} URLs")
        try:
            feats = extract_features(url)
            new_features.append(feats)
        except Exception:
            new_features.append(pd.DataFrame([{col: 0 for col in feature_cols}]))

    features_df = pd.concat(new_features, ignore_index=True)
    features_df['label'] = df['label'].values

    # Простая очистка: удаляем дубликаты и строки с NaN
    features_df = features_df.drop_duplicates(subset=feature_cols + ['label'])
    features_df = features_df.dropna(subset=feature_cols + ['label'])
    features_df = features_df.reset_index(drop=True)

    X = features_df[feature_cols].astype(np.float32).values
    y = features_df['label'].astype(int).values

    print(f"Final shape: {X.shape}")
    print(f"Classes: {dict(zip(*np.unique(y, return_counts=True)))}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Tuning Random Forest...")
    param_dist = {
        'n_estimators': [200, 300, 400],
        'max_depth': [10, 15, 20, None],
        'min_samples_split': [10, 20, 30],
        'min_samples_leaf': [2, 4, 6],
        'class_weight': ['balanced', 'balanced_subsample']
    }
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    search = RandomizedSearchCV(
        rf, param_dist, n_iter=20, cv=3,
        scoring='f1_weighted', n_jobs=-1, random_state=42
    )
    search.fit(X_train, y_train)
    best_rf = search.best_estimator_
    best_rf.n_jobs = 1

    y_pred = best_rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nBest params: {search.best_params_}")
    print(f"ACCURACY: {acc:.4f} ({acc*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], zero_division=0))

    test_urls = [
        ("https://google.com", 0),
        ("https://yandex.ru", 0),
        ("http://185.130.5.253/login", 1),
        ("https://bit.ly/fake", 1),
    ]
    print("\nCONTROL URL TEST")
    for url, true_label in test_urls:
        feats = extract_features(url)
        X_u = feats[feature_cols].astype(np.float32).values.reshape(1, -1)
        proba = best_rf.predict_proba(X_u)[0][1] * 100
        pred = 1 if proba >= 80 else 0
        status = "OK" if pred == true_label else "WARN"
        verdict = "DANGEROUS" if proba >= 80 else ("SUSPICIOUS" if proba >= 60 else "SAFE")
        print(f"{status} {url:40s} -> {proba:6.1f}% {verdict}")

    print("\nFeature Importances (top 10):")
    importances = best_rf.feature_importances_
    for name, imp in sorted(zip(feature_cols, importances), key=lambda x: -x[1])[:10]:
        print(f"  {name:25s}: {imp:.3f}")

    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(best_rf, BASE_DIR / 'ml' / 'model.pkl')
    print("Model saved to ml/model.pkl")

if __name__ == '__main__':
    main()