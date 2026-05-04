import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import sys
from pathlib import Path

from ml.features import extract_features

feature_cols = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
    'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
]

def main():
    BASE_DIR = Path(__file__).parent

    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    print(f"Loading dataset...")
    print(f"Shape: {df.shape}")
    print(f"Classes 0(legit)/1(phishing):\n{df['label'].value_counts()}")

    # safe urls
    safe_urls = [
        'https://google.com', 'https://yandex.ru', 'https://vk.com', 'https://github.com'
    ]
    new_safe = []
    for url in safe_urls:
        feats = extract_features(url).iloc[0].to_dict()
        new_safe.append(feats)

    if new_safe:
        safe_df = pd.DataFrame(new_safe)
        safe_df['label'] = 0
        safe_df['url'] = safe_urls
        df = pd.concat([df, safe_df], ignore_index=True)
        print(f"Added {len(new_safe)} safe URLs")

    # dangerous urls
    dangerous_urls = [
        'http://185.130.5.253/login', 'http://bit.ly/xxx'
    ]
    new_dangerous = []
    for url in dangerous_urls:
        feats = extract_features(url).iloc[0].to_dict()
        new_dangerous.append(feats)

    if new_dangerous:
        dangerous_df = pd.DataFrame(new_dangerous)
        dangerous_df['label'] = 1
        dangerous_df['url'] = dangerous_urls
        df = pd.concat([df, dangerous_df], ignore_index=True)
        print(f"Added {len(new_dangerous)} dangerous URLs")

    # convert types
    for col in feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df.dropna(subset=feature_cols).reset_index(drop=True)
    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    print(f"\nFinal dataset: {X.shape[0]} examples")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest...")
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("Training finished!")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")

    sample_size = 1000
    X_sample = X_test[:sample_size]
    start_time = time.perf_counter()
    _ = model.predict(X_sample)
    elapsed = time.perf_counter() - start_time
    avg_inference_time_ms = elapsed / sample_size * 1000
    print(f"\nInference time per URL: {avg_inference_time_ms:.4f} ms")

    print("\nCONTROL URL TEST")
    test_urls = ["https://google.com", "https://yandex.ru", "http://185.130.5.253/login"]
    for url in test_urls:
        feats = extract_features(url)
        proba = model.predict_proba(feats.values)[0][1] * 100
        if proba < 40:
            verdict = "SAFE"
        elif proba < 70:
            verdict = "SUSPICIOUS"
        else:
            verdict = "DANGEROUS"
        print(f"{url:<35} {proba:>6.1f}% {verdict}")

    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    print(f"\nModel saved to ml/model.pkl")

    # verify
    test_model = joblib.load(BASE_DIR / 'ml' / 'model.pkl')
    print(f"Verification: loaded model type = {type(test_model).__name__}")

if __name__ == '__main__':
    main()
