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
        print(f" Датасет не найден: {dataset_path}")
        sys.exit(1)

    df = pd.read_csv(dataset_path)
    print(f"Загружаем датасет...")
    print(f"Размер: {df.shape}")
    print(f"Классы 0(легит)/1(фишинг):\n{df['label'].value_counts()}")

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
        'https://linkedin.com'
    ]

    new_safe = []
    for url in safe_urls:
        # Если URL уже есть, не добавляем (но для чистоты можно добавить)
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url).iloc[0].to_dict()
        new_safe.append(feats)

    if new_safe:
        safe_df = pd.DataFrame(new_safe)
        safe_df['label'] = 0
        safe_df['url'] = safe_urls[:len(new_safe)]
        df = pd.concat([df, safe_df], ignore_index=True)
        print(f" Добавлено {len(new_safe)} безопасных URL")

    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://185.130.5.253/secure',
        'http://bit.ly/3xYz7Kq',
        'http://tinyurl.com/secure-login',
        'http://login.secure-update.ru/account/verify',
        'http://paypal.com.secure-login.xyz/login'
    ]

    new_dangerous = []
    for url in dangerous_urls:
        if 'url' in df.columns and url in df['url'].values:
            continue
        feats = extract_features(url).iloc[0].to_dict()
        new_dangerous.append(feats)

    if new_dangerous:
        dangerous_df = pd.DataFrame(new_dangerous)
        dangerous_df['label'] = 1
        dangerous_df['url'] = dangerous_urls[:len(new_dangerous)]
        df = pd.concat([df, dangerous_df], ignore_index=True)
        print(f" Добавлено {len(new_dangerous)} опасных URL")

    for col in feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.dropna(subset=feature_cols).reset_index(drop=True)

    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    print(f"\nИтоговый датасет: {X.shape[0]} примеров, {X.shape[1]} признаков")
    print(f"Распределение классов: 0={np.sum(y==0)}, 1={np.sum(y==1)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

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
    print(" Обучение завершено!")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n ТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\n Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Легитимные', 'Фишинг']))

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\n ТОП-10 ПРИЗНАКОВ:")
    print(f"{'Признак':<20} {'Важность'}")
    print("-" * 30)
    for i in range(len(feature_cols)):
        print(f"{feature_cols[indices[i]]:<20} {importances[indices[i]]:.4f}")

    sample_size = 1000
    X_sample = X_test[:sample_size]
    start_time = time.perf_counter()
    _ = model.predict(X_sample)
    elapsed = time.perf_counter() - start_time
    avg_inference_time = elapsed / sample_size * 1000  # мс
    print(f"\n Среднее время инференса: {avg_inference_time:.4f} мс/URL")

    print("\n" + "="*70)
    print(" ТЕСТ НА КОНТРОЛЬНЫХ URL")
    print("="*70)
    print(f"{'URL':<35} {'Риск %':<8} {'Вердикт'}")
    print("-"*70)

    test_urls = [
        "https://google.com",
        "https://yandex.ru",
        "https://github.com",
        "https://login-verify.com",
        "http://185.130.5.253/login",
        "http://bit.ly/xxx"
    ]

    for url in test_urls:
        feats = extract_features(url)
        if hasattr(feats, 'values'):
            X_input = feats.values
        else:
            X_input = np.array(feats).reshape(1, -1)
        proba = model.predict_proba(X_input)[0][1] * 100
        if proba < 55:
            verdict = "🟢 БЕЗОПАСНО"
        elif proba < 85:
            verdict = "🟡 ПОДОЗРИТЕЛЬНО"
        else:
            verdict = "🔴 ОПАСНО"
        print(f"{url:<35} {proba:>6.1f}% {verdict}")

    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print(f"\n Модель сохранена: ml/model.pkl")

if __name__ == '__main__':
    main()
