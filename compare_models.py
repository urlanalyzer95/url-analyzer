# compare_models.py
import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
import xgboost as xgb
import joblib
import os

# Импортируем признаки из единого источника
from ml.features import feature_cols as FEATURE_NAMES

def main():
    print("Поиск датасета...")
    possible_files = [
        'data/processed/url_dataset_features.csv',
        'url_dataset_features.csv',
        '../data/processed/url_dataset_features.csv'
    ]
    
    df = None
    for fname in possible_files:
        if os.path.exists(fname):
            print(f"✅ Найден: {fname}")
            df = pd.read_csv(fname)
            break
    
    if df is None:
        print("❌ Датасет не найден!")
        return
    
    # Подготовка данных
    df = df.dropna(subset=FEATURE_NAMES)
    X = df[FEATURE_NAMES].astype(np.float32).values
    y = df['label'].astype(int).values
    
    print(f"📊 Датасет: {X.shape[0]} примеров, {X.shape[1]} признаков")
    print(f"📈 Классы: {dict(zip(*np.unique(y, return_counts=True)))}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # === Random Forest ===
    print("\n🌲 Random Forest...")
    rf_start = time.time()
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=15, class_weight='balanced',
        random_state=42, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_time = time.time() - rf_start
    
    rf_pred = rf.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_pred)
    rf_f1 = f1_score(y_test, rf_pred)
    print(f"RF: Accuracy={rf_acc:.4f}, F1={rf_f1:.4f}, Time={rf_time:.2f}s")
    
    # === XGBoost ===
    print("\n🚀 XGBoost...")
    xgb_start = time.time()
    xgb_model = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        random_state=42, n_jobs=-1, use_label_encoder=False,
        eval_metric='logloss'
    )
    xgb_model.fit(X_train, y_train)
    xgb_time = time.time() - xgb_start
    
    xgb_pred = xgb_model.predict(X_test)
    xgb_acc = accuracy_score(y_test, xgb_pred)
    xgb_f1 = f1_score(y_test, xgb_pred)
    print(f"XGB: Accuracy={xgb_acc:.4f}, F1={xgb_f1:.4f}, Time={xgb_time:.2f}s")
    
    # === Победитель ===
    print("\n" + "="*50)
    if rf_acc >= xgb_acc:
        print(f"🏆 ПОБЕДИТЕЛЬ: Random Forest (Accuracy={rf_acc:.4f})")
        joblib.dump(rf, 'ml/model.pkl')
        print("💾 Сохранено: ml/model.pkl")
    else:
        print(f"🏆 ПОБЕДИТЕЛЬ: XGBoost (Accuracy={xgb_acc:.4f})")
        joblib.dump(xgb_model, 'ml/model.pkl')
        print("💾 Сохранено: ml/model.pkl")
    print("="*50)

if __name__ == '__main__':
    main()
