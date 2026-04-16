import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

def main():
    # Корень проекта
    BASE_DIR = Path(__file__).parent
    
    # 1. Загрузка датасета
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    if not dataset_path.exists():
        print(f"❌ Датасет не найден: {dataset_path}")
        print("Создайте папку data/processed/ и положите туда url_dataset_features.csv")
        sys.exit(1)
    
    df = pd.read_csv(dataset_path)
    
    feature_cols = [
        'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
        'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
        'has_cp.php', 'has_admin', 'is_shortened', 'domain_length'
    ]
    
    if not all(col in df.columns for col in feature_cols):
        print(" Ошибка: не все признаки в датасете!")
        print("Нужны:", feature_cols)
        sys.exit(1)
    
    X = df[feature_cols]
    y = df['label']
    
    # 3. Разделение 
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Random Forest 
    model = RandomForestClassifier(
        n_estimators=200,        # Деревьев
        max_depth=15,           # Глубина
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1               # Все CPU
    )
    model.fit(X_train, y_train)
    
    # 5. Тестирование
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n ТОЧНОСТЬ: {accuracy:.4f} ({accuracy*100:.2f}%)")
     
    # 8. СОХРАНЕНИЕ
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    joblib.dump(model, BASE_DIR / 'ml' / 'model.pkl')
    joblib.dump(feature_cols, BASE_DIR / 'ml' / 'feature_cols.pkl')
    

if __name__ == '__main__':
    main()
