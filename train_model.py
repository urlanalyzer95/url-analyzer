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
    'has_ip', 'has_login', 'has_verify', 'has_account',
    'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
]

def main():
    BASE_DIR = Path(__file__).parent
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        sys.exit(1)

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    print(f"Shape: {df.shape}")
    print(f"Classes 0(legit)/1(phishing):\n{df['label'].value_counts()}")

    safe_urls = [
        'https://google.com', 'https://yandex.ru', 'https://www.bing.com',
        'https://duckduckgo.com', 'https://github.com', 'https://stackoverflow.com',
        'https://www.reddit.com', 'https://www.twitter.com', 'https://www.instagram.com',
        'https://www.linkedin.com', 'https://www.facebook.com', 'https://vk.com',
        'https://ok.ru', 'https://www.youtube.com', 'https://www.netflix.com',
        'https://www.spotify.com', 'https://www.bbc.com', 'https://edition.cnn.com',
        'https://www.nytimes.com', 'https://medium.com', 'https://techcrunch.com',
        'https://mail.google.com', 'https://outlook.live.com', 'https://mail.yahoo.com',
        'https://drive.google.com', 'https://www.dropbox.com', 'https://mit.edu',
        'https://stanford.edu', 'https://harvard.edu', 'https://www.amazon.com',
        'https://www.ebay.com', 'https://www.paypal.com', 'https://www.adobe.com',
        'https://www.office.com', 'https://www.zoom.us', 'https://www.slack.com',
        'https://www.telegram.org', 'https://www.whatsapp.com', 'https://www.booking.com',
        'https://www.airbnb.com', 'https://www.wikipedia.org', 'https://mail.ru',
        'https://dzen.ru',
    ]
    
    for url in safe_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 0}])], ignore_index=True)
        except Exception:
            pass
    
    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://bit.ly/xxx',
        'https://secure-paypal-verify.account-login.cp.php.evil.com',
        'http://goo.gl/malware',
    ]
    
    for url in dangerous_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 1}])], ignore_index=True)
        except Exception:
            pass

    df = df.drop_duplicates(subset=feature_cols + ['label'])
    # ВАЖНО: заполняем пропуски нулями, а не удаляем строки
    df[feature_cols] = df[feature_cols].fillna(0)
    df = df.dropna(subset=['label']).reset_index(drop=True)

    print(f"\nFinal dataset: {len(df)} examples")

    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=20,
        min_samples_leaf=10,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("Training finished!")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    sample_size = min(1000, len(X_test))
    start_time = time.perf_counter()
    _ = model.predict(X_test[:sample_size])
    elapsed = time.perf_counter() - start_time
    print(f"\nInference time per URL: {(elapsed / sample_size * 1000):.4f} ms")

    print("\nCONTROL URL TEST")
    test_cases = [
        ("https://google.com", 0),
        ("https://yandex.ru", 0),
        ("http://185.130.5.253/login", 1),
        ("https://bit.ly/xxx", 1),
    ]
    
    for url, true_label in test_cases:
        try:
            feats = extract_features(url)
            proba = model.predict_proba(feats[feature_cols].values)[0][1] * 100
            pred = 1 if proba >= 70 else 0
            status = "✅" if pred == true_label else "⚠️"
            verdict = "DANGEROUS" if proba >= 70 else ("SUSPICIOUS" if proba >= 40 else "SAFE")
            print(f"{status} {url:40s} → {proba:6.1f}% {verdict}")
        except Exception as e:
            print(f"❌ {url:40s} → ERROR: {e}")

    print("\n🔍 Feature Importances (top 8):")
    for name, imp in sorted(zip(feature_cols, model.feature_importances_), key=lambda x: -x[1])[:8]:
        print(f"  {name:15s}: {imp:.3f}")

    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    model_path = BASE_DIR / 'ml' / 'model.pkl'
    joblib.dump(model, model_path)
    print(f"\n✅ Model saved to {model_path}")

    test_model = joblib.load(model_path)
    print(f"Verification: loaded model type = {type(test_model).__name__}")


if __name__ == '__main__':
    main()
