import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sys
import re
from pathlib import Path
from urllib.parse import urlparse

def extract_features(url):
    """Встроенная функция извлечения признаков для тестов"""
    feature_cols = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
        'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
        'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
    ]
    
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_params'] = len(re.findall(r'[?&]', url))
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0
    features['has_https'] = 1 if url.startswith('https://') else 0
    features['has_login'] = 1 if 'login' in url.lower() else 0
    features['has_verify'] = 1 if 'verify' in url.lower() else 0
    features['has_account'] = 1 if 'account' in url.lower() else 0
    features['has_cp.php'] = 1 if 'cp.php' in url.lower() else 0
    features['has_admin'] = 1 if 'admin' in url.lower() else 0
    features['is_shortened'] = 1 if any(x in url.lower() for x in ['bit.ly','tinyurl','t.co']) else 0
    
    try:
        domain = re.search(r'https?://([^/]+)', url).group(1) if '://' in url else url.split('/')[0]
        features['domain_length'] = len(domain.replace('.',''))
    except:
        features['domain_length'] = 0
    
    return pd.DataFrame([features])[feature_cols]

def main():
    BASE_DIR = Path(__file__).parent
    
    # 1. Загрузка датасета
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
    print("✅ Обучение завершено!")
    
    # Предсказание и оценка
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n🎯 ТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['🟢 Легитимные', '🔴 Фишинг']))
    
    # Важность признаков
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\n🏆 ТОП-10 ПРИЗНАКОВ:")
    print(f"{'Признак':<20} {'Важность':<10}")
    print("-" * 30)
    for i in range(len(feature_cols)):
        print(f"{feature_cols[indices[i]]:<20} {importances[indices[i]]:.4f}")
    
    # Время инференса
    sample_size = 1000
    X_sample = X_test[:sample_size]
    start_time = time.perf_counter()
    _ = model.predict(X_sample)
    elapsed = time.perf_counter() - start_time
    avg_inference_time = elapsed / sample_size * 1000
    print(f"\n⚡ Среднее время инференса: {avg_inference_time:.4f} мс/URL")
    
    # 🧪 ТЕСТ РЕАЛЬНЫХ URL
    print("\n" + "="*60)
    print("🧪 ТЕСТ НА РЕАЛЬНЫХ URL")
    print("="*60)
    
    test_urls = [
        "https://google.com",
        "https://yandex.ru", 
        "https://vk.com",
        "https://github.com",
        "http://185.13.55.2/admin",
        "https://bit.ly/abc",
        "https://fake-login-verify.com",
        "http://admin.cp.php/login"
    ]
    
    print(f"{'URL':<35} {'Вероятность фишинга':<15} {'Вердикт'}")
    print("-"*70)
    
    for url in test_urls:
        try:
            features = extract_features(url)
            proba = model.predict_proba(features)[0][1] * 100
            
            if proba < 40:
                verdict = "🟢 БЕЗОПАСНО"
            elif proba < 70:
                verdict = "🟡 ПОДОЗРИТЕЛЬНО"
            else:
                verdict = "🔴 ОПАСНО"
                
            print(f"{url:<35} {proba:>7.1f}%{verdict}")
        except Exception as e:
            print(f"{url:<35} ОШИБКА: {e}")
    
    # Сохранение модели
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print(f"\n💾 Модель сохранена: ml/model.pkl")
    print("🚀 ПРОДАКШЕН-ГОТОВА!")

if __name__ == '__main__':
    main()
