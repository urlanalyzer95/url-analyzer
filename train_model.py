import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sys
from pathlib import Path

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
    print("Обучение завершено!")
    
    # Предсказание и оценка
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['0', '1']))
    
    # Важность признаков
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\nТОП-10 ПРИЗНАКОВ:")
    print(f"{'feature':<20} importance")
    for i in range(min(10, len(feature_cols))):
        print(f"{feature_cols[indices[i]]:<20} {importances[indices[i]]:.4f}")
    
    # Время инференса (среднее на один URL)
    # Берём небольшую выборку из тестового набора для замеров
    sample_size = 1000
    X_sample = X_test[:sample_size]
    start_time = time.perf_counter()
    _ = model.predict(X_sample)
    elapsed = time.perf_counter() - start_time
    avg_inference_time = elapsed / sample_size * 1000  # в миллисекундах
    print(f"\nСреднее время инференса (на 1 URL): {avg_inference_time:.4f} мс")
    
    # Сохранение модели
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    print("\nМодель сохранена в ml/model.pkl")

if __name__ == '__main__':
    main()
