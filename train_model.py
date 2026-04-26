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

    # 1. Загрузка основного датасета
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if not dataset_path.exists():
        print(f"❌ Датасет не найден: {dataset_path}")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    print(f"Загружаем датасет...")
    print(f"Размер: {df.shape}")
    print(f"Классы 0(легит)/1(фишинг):\n{df['label'].value_counts()}")

    feature_cols = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
        'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
        'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
    ]

    # ---------- 2. Добавление безопасных URL (label=0) ----------
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
        'https://whatsapp.com',
        'https://telegram.org',
        'https://zoom.us',
        'https://netflix.com',
        'https://spotify.com',
        'https://twitch.tv',
        'https://discord.com',
        'https://yahoo.com',
        'https://bing.com'
    ]

    new_safe = []
    for url in safe_urls:
        # Пропускаем, если URL уже есть в датасете
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url)
        new_safe.append(feats)

    if new_safe:
        safe_df = pd.DataFrame(new_safe, columns=feature_cols)
        safe_df['label'] = 0
        safe_df['url'] = safe_urls[:len(new_safe)]
        df = pd.concat([df, safe_df], ignore_index=True)
        print(f"Добавлено {len(new_safe)} безопасных URL")

    # ---------- 3. Добавление опасных URL (label=1) ----------
    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://185.130.5.253/secure',
        'http://bit.ly/3xYz7Kq',
        'http://tinyurl.com/secure-login',
        'http://goo.gl/verify-account',
        'http://login.secure-update.ru/account/verify',
        'http://paypal.com.secure-login.xyz/login'
    ]

    new_dangerous = []
    for url in dangerous_urls:
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url)
        new_dangerous.append(feats)

    if new_dangerous:
        dangerous_df = pd.DataFrame(new_dangerous, columns=feature_cols)
        dangerous_df['label'] = 1
        dangerous_df['url'] = dangerous_urls[:len(new_dangerous)]
        df = pd.concat([df, dangerous_df], ignore_index=True)
        print(f"Добавлено {len(new_dangerous)} опасных URL")

    # ----------------------------------------------

    X = df[feature_cols]
    y = df['label']

    # Разделение
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nПризнаков: {X.shape[1]}")
    print(f"Train: {X_train.shape}")
    print(f"Test: {X_test.shape}")

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

    # Оценка
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['legitimate', 'phishing']))

    # Важность признаков
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

    # ---------- Ручная проверка на контрольных URL ----------
    print("\n🔍 Проверка на контрольных URL:")
    test_urls = [
        ('https://google.com', 'ожидается safe (≈0%)'),
        ('https://yandex.ru', 'ожидается safe (≈0%)'),
        ('https://github.com', 'ожидается safe (≈0%)'),
        ('https://login-verify.com', 'ожидается suspicious (~50%)?'),
        ('http://185.130.5.253/login', 'ожидается dangerous (>90%)'),
        ('http://bit.ly/xxx', 'ожидается dangerous (>90%)'),
    ]
    for url, note in test_urls:
        feats = extract_features(url)
        proba = model.predict_proba([feats])[0][1]
        print(f"{url:50} {proba:.2%}   ({note})")
    # ------------------------------------------------

    # Сохранение
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print("\n✅ Модель сохранена в ml/model.pkl")

if __name__ == '__main__':
    main()
