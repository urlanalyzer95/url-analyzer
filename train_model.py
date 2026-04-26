1. ФИКС ml/features.py — добавь feature_cols на экспорт:
python
# ml/features.py — КОНЕЦ файла добавь:
feature_cols = ['url_length','num_dots','num_hyphens','num_slashes','num_params',
                'has_ip','has_https','has_login','has_verify','has_account',
                'has_cp.php','has_admin','is_shortened','domain_length']

# ✅ Теперь импортируется!
2. ИСПРАВЛЕННЫЙ train_model.py (полный код):
python
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

# ✅ Импорт ТОЛЬКО extract_features (feature_cols определим здесь)
from ml.features import extract_features

# ✅ Определяем feature_cols ЛОКАЛЬНО (безопасно!)
feature_cols = ['url_length','num_dots','num_hyphens','num_slashes','num_params',
                'has_ip','has_https','has_login','has_verify','has_account',
                'has_cp.php','has_admin','is_shortened','domain_length']

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

    # 2. ДОБАВЛЯЕМ БЕЗОПАСНЫЕ URL
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
        print(f"✅ Добавлено {len(new_safe)} безопасных URL")

    # 3. ДОБАВЛЯЕМ ОПАСНЫЕ URL
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
        print(f"✅ Добавлено {len(new_dangerous)} опасных URL")

    # 4. ПОДГОТОВКА
    for col in feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df.dropna(subset=feature_cols).reset_index(drop=True)
    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    print(f"\nИтоговый датасет: {X.shape[0]} примеров")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 5. ОБУЧЕНИЕ
    print("\nОбучаем Random Forest...")
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("✅ Обучение завершено!")

    # 6. ОЦЕНКА
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n🎯 ТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")

    # 🧪 ТЕСТ КОНТРОЛЬНЫХ URL (✅ ФИКС predict_proba!)
    print("\n" + "="*60)
    print("🧪 ТЕСТ КОНТРОЛЬНЫХ URL")
    print("="*60)
    print(f"{'URL':<35} {'Риск %':<8} {'Вердикт'}")
    print("-"*60)
    
    test_urls = ["https://google.com", "https://yandex.ru", "http://185.130.5.253/login"]
    for url in test_urls:
        feats = extract_features(url)
        proba = model.predict_proba(feats.values)[0][1] * 100  # ✅ .values!
        color = "🟢" if proba < 40 else "🟡" if proba < 70 else "🔴"
        print(f"{url:<35} {proba:>6.1f}% {color}")

    # СОХРАНЕНИЕ
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print(f"\n💾 Модель сохранена!")
    print("🚀 ПРОДАКШЕН-ГОТОВА!")

if __name__ == '__main__':
    main()
