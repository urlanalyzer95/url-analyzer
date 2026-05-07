# train_model.py
import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import sys
import os
from pathlib import Path

from ml.features import extract_features, feature_cols

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

    # === Добавление дополнительных легитимных и опасных URL ===
    safe_urls = [
        'https://google.com', 'https://yandex.ru', 'https://www.microsoft.com',
        'https://www.apple.com', 'https://www.amazon.com', 'https://www.wikipedia.org',
        'https://mail.google.com', 'https://github.com', 'https://stackoverflow.com',
        'https://www.youtube.com', 'https://www.netflix.com', 'https://www.paypal.com',
        'https://accounts.google.com', 'https://login.live.com', 'https://www.linkedin.com',
    ]
    
    for url in safe_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 0}])], ignore_index=True)
        except:
            pass  # Пропускаем, если не удалось извлечь признаки
    
    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://bit.ly/xxx',
        'https://secure-paypal-verify.account-login.cp.php.evil.com',
    ]
    
    for url in dangerous_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 1}])], ignore_index=True)
        except:
            pass

    # === Очистка данных ===
    df = df.drop_duplicates(subset=feature_cols + ['label'])
    df[feature_cols] = df[feature_cols].fillna(0)
    df = df.dropna(subset=feature_cols).reset_index(drop=True)

    print(f"\nFinal dataset: {len(df)} examples")

    # === Подготовка матриц ===
    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # === Обучение модели ===
    print("\nTraining Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight='balanced',  # Важно для баланса классов
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("Training finished!")

    # === Оценка ===
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # === Замер скорости ===
    sample_size = min(1000, len(X_test))
    start_time = time.perf_counter()
    _ = model.predict(X_test[:sample_size])
    elapsed = time.perf_counter() - start_time
    print(f"\nInference time per URL: {(elapsed / sample_size * 1000):.4f} ms")

    # === Контрольный тест ===
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
            proba = model.predict_proba(feats.values)[0][1] * 100
            pred = 1 if proba >= 70 else 0
            status = "✅" if pred == true_label else "⚠️"
            verdict = "DANGEROUS" if proba >= 70 else ("SUSPICIOUS" if proba >= 40 else "SAFE")
            print(f"{status} {url:40s} → {proba:6.1f}% {verdict}")
        except Exception as e:
            print(f"❌ {url:40s} → ERROR: {e}")

    # === Сохранение модели ===
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    model_path = BASE_DIR / 'ml' / 'model.pkl'
    joblib.dump(model, model_path)
    print(f"\n✅ Model saved to {model_path}")

    # === Верификация ===
    test_model = joblib.load(model_path)
    print(f"Verification: loaded model type = {type(test_model).__name__}")

if __name__ == '__main__':
    main()
