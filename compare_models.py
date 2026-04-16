import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report
import xgboost as xgb
import joblib
import os

FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 'num_params',
    'has_ip', 'has_https', 'has_login', 'has_verify', 'has_account',
    'has_admin', 'has_cp_php', 'is_shortened', 'domain_length'
]

def extract_features(url):
    import re
    from urllib.parse import urlparse
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_params'] = url.count('?') + url.count('&')
    features['has_ip'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features['has_https'] = 1 if url.startswith('https') else 0
    suspicious = ['login', 'verify', 'account', 'admin', 'cp.php']
    for word in suspicious:
        key = f'has_{word.replace(".", "_").replace("?", "")}'
        features[key] = 1 if word.lower() in url.lower() else 0
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
    features['is_shortened'] = 1 if any(s in url.lower() for s in shorteners) else 0
    parsed = urlparse(url)
    features['domain_length'] = len(parsed.netloc) if parsed.netloc else 0
    return [features[name] for name in FEATURE_NAMES]

print(" Поиск датасета...")
possible_files = [
    'url_dataset_features.csv',
    'data/processed/url_dataset_features.csv',
    'data/url_dataset_features.csv'
]

df = None
for fname in possible_files:
    if os.path.exists(fname):
        print(f" Найден: {fname}")
        df = pd.read_csv(fname)
        X = df[FEATURE_NAMES]
        y = df['label']
        break

if df is None:
    print(" Датасет не найден!")
    exit(1)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\n Random Forest...")
rf_start = time.time()
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_time = time.time() - rf_start

rf_pred = rf.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
rf_f1 = f1_score(y_test, rf_pred)
print(f" RF: Accuracy={rf_acc:.4f}, F1={rf_f1:.4f}, Time={rf_time:.2f}s")

print("\n XGBoost...")
xgb_start = time.time()
xgb_model = xgb.XGBClassifier(
    n_estimators=200, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8, random_state=42, n_jobs=-1
)
xgb_model.fit(X_train, y_train)
xgb_time = time.time() - xgb_start

xgb_pred = xgb_model.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
xgb_f1 = f1_score(y_test, xgb_pred)
print(f" XGB: Accuracy={xgb_acc:.4f}, F1={xgb_f1:.4f}, Time={xgb_time:.2f}s")


winner = "Random Forest" if rf_acc > xgb_acc else "XGBoost"
print(f"\n ПОБЕДИТЕЛЬ: **{winner}** ({max(rf_acc, xgb_acc):.4f})")
