import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import accuracy_score, classification_report
import joblib
import sys
import os
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

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    print(f"Shape: {df.shape}")
    print(f"Classes 0(legit)/1(phishing):\n{df['label'].value_counts()}")

    # 1. Удаление дубликатов по признакам + метке
    df = df.drop_duplicates(subset=feature_cols + ['label'])

    # 2. Заполнение пропусков (на случай битых строк в исходном CSV)
    df[feature_cols] = df[feature_cols].fillna(0)

    # 3. Балансировка классов (если дисбаланс > 10%)
    class_counts = df['label'].value_counts()
    if abs(class_counts[0] - class_counts[1]) / class_counts.sum() > 0.1:
        from sklearn.utils import resample
        df_majority = df[df['label'] == class_counts.idxmax()]
        df_minority = df[df['label'] == class_counts.idxmin()]
        df_minority_upsampled = resample(df_minority, replace=True, 
                                         n_samples=len(df_majority), random_state=42)
        df = pd.concat([df_majority, df_minority_upsampled])
        print(f"✅ Классы сбалансированы: {len(df)} примеров")

    print(f"\nFinal dataset: {len(df)} examples")

    # 4. Подготовка матриц
    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 5. Обучение с калибровкой вероятностей
    print("\nTraining Random Forest + Calibration...")
    base_model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    # CalibratedClassifierCV делает вероятности адекватными (решает проблему google.com → 73%)
    model = CalibratedClassifierCV(base_model, method='sigmoid', cv=5)
    model.fit(X_train, y_train)
    print("Training finished!")

    # 6. Оценка на тесте
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # 7. Замер времени инференса
    sample_size = min(1000, len(X_test))
    start_time = time.perf_counter()
    _ = model.predict(X_test[:sample_size])
    elapsed = time.perf_counter() - start_time
    print(f"\nInference time per URL: {(elapsed / sample_size * 1000):.4f} ms")

    # 8. Контрольный тест
    print("\nCONTROL URL TEST")
    test_urls = ["https://google.com", "https://yandex.ru", "http://185.130.5.253/login"]
    for url in test_urls:
        try:
            feats = extract_features(url)
            proba = model.predict_proba(feats.values)[0][1] * 100
            if proba < 40:
                verdict = "SAFE"
            elif proba < 70:
                verdict = "SUSPICIOUS"
            else:
                verdict = "DANGEROUS"
            print(f"{url:40s} → {proba:6.1f}% {verdict}")
        except Exception as e:
            print(f"{url:40s} → ERROR: {e}")

    # 9. Сохранение модели
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    print(f"\n✅ Model saved to ml/model.pkl")

    # 10. Проверка корректности сохранения
    test_model = joblib.load(BASE_DIR / 'ml' / 'model.pkl')
    print(f"Verification: loaded model type = {type(test_model).__name__}")

if __name__ == '__main__':
    main()
