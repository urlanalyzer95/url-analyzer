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

def main():
    BASE_DIR = Path(__file__).parent
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if not dataset_path.exists():
        print(f"❌ Датасет не найден: {dataset_path}")
        sys.exit(1)

    # Загрузка основного датасета
    df = pd.read_csv(dataset_path)
    print(f"Загружено: {df.shape}")
    print(f"Классы:\n{df['label'].value_counts()}")

    feature_cols = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
        'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
        'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
    ]

    # Добавление безопасных и опасных примеров через списки
    additional_data = []  # (features, label)

    safe_urls = [
        'https://google.com',
        'https://yandex.ru',
        'https://github.com',
        'https://stackoverflow.com',
        'https://vk.com',
        'https://wikipedia.org',
        'https://youtube.com',
        'https://instagram.com',
        'https://facebook.com',
        'https://twitter.com',
        'https://amazon.com',
        'https://apple.com',
        'https://microsoft.com',
        'https://reddit.com',
        'https://linkedin.com',
    ]
    for url in safe_urls:
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url)
        additional_data.append((feats, 0))

    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://bit.ly/3xYz7Kq',
        'http://tinyurl.com/secure-login',
        'http://login.secure-update.ru/account/verify',
    ]
    for url in dangerous_urls:
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url)
        additional_data.append((feats, 1))

    # Создаём массивы признаков и меток из исходного датасета
    X = df[feature_cols].values.astype(np.float32)
    y = df['label'].values.astype(np.int32)

    # Добавляем новые данные в конец
    for feats, label in additional_data:
        X = np.vstack([X, np.array(feats, dtype=np.float32)])
        y = np.append(y, label)

    print(f"После добавления: {X.shape[0]} примеров, {X.shape[1]} признаков")
    print(f"Распределение классов: 0={np.sum(y==0)}, 1={np.sum(y==1)}")

    # Разделение
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    # Обучение
    print("\nОбучаем Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("Обучение завершено!")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['legitimate', 'phishing']))

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\nТОП-10 ПРИЗНАКОВ:")
    print(f"{'feature':<20} importance")
    for i in range(min(10, len(feature_cols))):
        print(f"{feature_cols[indices[i]]:<20} {importances[indices[i]]:.4f}")

    # Время инференса
    sample_size = 1000
    X_sample = X_test[:sample_size]
    start = time.perf_counter()
    _ = model.predict(X_sample)
    elapsed = time.perf_counter() - start
    avg_ms = elapsed / sample_size * 1000
    print(f"\nСреднее время инференса (на 1 URL): {avg_ms:.4f} мс")

    # Ручная проверка
    print("\n🔍 Проверка на контрольных URL:")
    test_urls = [
        ('https://google.com', 'safe'),
        ('https://yandex.ru', 'safe'),
        ('https://github.com', 'safe'),
        ('https://login-verify.com', '?'),
        ('http://185.130.5.253/login', 'dangerous'),
        ('http://bit.ly/xxx', 'dangerous'),
    ]
    for url, note in test_urls:
        feats = extract_features(url)
        proba = model.predict_proba([np.array(feats, dtype=np.float32)])[0][1]
        print(f"{url:50} {proba:.2%}   ({note})")

    # Сохранение
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print("\n✅ Модель сохранена в ml/model.pkl")

if __name__ == '__main__':
    main()
