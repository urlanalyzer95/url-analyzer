import pandas as pd
import numpy as np
import time
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import xgboost as xgb
import joblib
import os
from pathlib import Path
from ml.features import extract_features, feature_cols

def add_massive_safe_urls(features_df):
    domains = [
        'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'reddit.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org', 'microsoft.com', 'apple.com',
        'amazon.com', 'ebay.com', 'paypal.com', 'adobe.com', 'dropbox.com',
        'zoom.us', 'skype.com', 'whatsapp.com', 'telegram.org',
        'coursera.org', 'stepik.org', 'habr.com', 'medium.com',
        'bbc.com', 'cnn.com', 'nytimes.com', 'theguardian.com',
        'reuters.com', 'bloomberg.com', 'forbes.com',
        'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk', 'cam.ac.uk',
        'berkeley.edu', 'ucla.edu', 'columbia.edu', 'princeton.edu', 'yale.edu',
        'yandex.ru', 'mail.ru', 'vk.com', 'ok.ru', 'gosuslugi.ru',
        'sberbank.ru', 'ozon.ru', 'wildberries.ru', 'avito.ru', 'hh.ru',
        'rbc.ru', 'lenta.ru', 'ria.ru', 'tass.ru', '1tv.ru', 'vesti.ru',
        'univ-orel.ru', 'oreluniver.ru', 'sdo.univ-orel.ru',
        'mgu-russian.ru', 'hse.ru', 'spbu.ru', 'kpfu.ru', 'urfu.ru',
        'nsu.ru', 'bmstu.ru', 'mirea.ru', 'mipt.ru',
    ]
    paths = [
        '/', '/about', '/contact', '/blog', '/news', '/events',
        '/products', '/services', '/support', '/faq', '/help',
        '/terms', '/privacy', '/careers', '/press', '/investors',
        '/login', '/register', '/signup', '/account', '/profile',
        '/dashboard', '/settings', '/search', '/article', '/post',
        '/page', '/video', '/image', '/download', '/upload',
    ]

    new_rows = []
    for domain in domains:
        for scheme in ['https://', 'http://']:
            for path in paths:
                url = f"{scheme}{domain}{path}"
                try:
                    feats = extract_features(url)
                    new_rows.append(feats)
                except Exception:
                    continue

    if new_rows:
        safe_df = pd.concat(new_rows, ignore_index=True)
        safe_df['label'] = 0
        return pd.concat([features_df, safe_df], ignore_index=True)
    return features_df

def add_phishing_shorteners(features_df, count=12000):
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd',
                  'buff.ly', 'shorte.st', 'bc.vc', 'adf.ly']
    suspicious_words = ['login', 'verify', 'account', 'admin', 'cp.php', 
                        'secure', 'update', 'signin', 'webscr', 'paypal',
                        'confirm', 'password', 'reset', 'unlock', 'billing',
                        'authenticate', 'validation', 'credential']

    new_rows = []
    rng = np.random.RandomState(42)
    for _ in range(count):
        shortener = rng.choice(shorteners)
        suffix = ''.join(rng.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), size=rng.randint(4, 12)))
        word = rng.choice(suspicious_words)
        url = f"https://{shortener}/{suffix}/{word}"
        try:
            feats = extract_features(url)
            feats['label'] = 1
            new_rows.append(feats)
        except Exception:
            continue

    if new_rows:
        phish_df = pd.concat(new_rows, ignore_index=True)
        return pd.concat([features_df, phish_df], ignore_index=True)
    return features_df

def main():
    BASE_DIR = Path(__file__).parent
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'

    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        return

    print("Loading and preparing dataset...")
    df = pd.read_csv(dataset_path)

    if 'url' not in df.columns:
        raise ValueError("CSV must contain 'url' column")

    new_features = []
    for url in df['url']:
        try:
            feats = extract_features(url)
            new_features.append(feats)
        except Exception:
            new_features.append(pd.DataFrame([{col: 0 for col in feature_cols}]))
    features_df = pd.concat(new_features, ignore_index=True)
    features_df['label'] = df['label'].values

    features_df = add_massive_safe_urls(features_df)
    features_df = add_phishing_shorteners(features_df, count=12000)

    features_df = features_df.drop_duplicates(subset=feature_cols + ['label'])
    features_df = features_df.dropna(subset=feature_cols + ['label'])
    features_df = features_df.reset_index(drop=True)

    X = features_df[feature_cols].astype(np.float32).values
    y = features_df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    print("Balancing with SMOTE...")
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=10,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1,          # после SMOTE классы сбалансированы
        random_state=42,
        n_jobs=1,
        eval_metric='logloss'
    )
    xgb_model.fit(
        X_train_bal, y_train_bal,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    y_pred = xgb_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {acc:.4f} ({acc*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], zero_division=0))

    test_urls = [
        ("https://google.com", 0),
        ("https://yandex.ru", 0),
        ("https://oreluniver.ru/schedule", 0),
        ("http://sdo.univ-orel.ru/", 0),
        ("http://185.130.5.253/login", 1),
        ("https://bit.ly/fake", 1),
        ("https://t.co/abc123login", 1),          # дополнительный сокращённый URL
    ]
    print("\nCONTROL URL TEST")
    for url, true_label in test_urls:
        try:
            feats = extract_features(url)
            X_u = feats[feature_cols].astype(np.float32).values.reshape(1, -1)
            proba = xgb_model.predict_proba(X_u)[0][1] * 100
            pred = 1 if proba >= 80 else 0
            status = "OK" if pred == true_label else "WARN"
            verdict = "DANGEROUS" if proba >= 80 else ("SUSPICIOUS" if proba >= 60 else "SAFE")
            print(f"{status} {url:50s} -> {proba:6.1f}% {verdict}")
        except Exception as e:
            print(f"ERROR {url:50s} -> {e}")

    print("\nFeature Importances (top 10):")
    importances = xgb_model.feature_importances_
    for name, imp in sorted(zip(feature_cols, importances), key=lambda x: -x[1])[:10]:
        print(f"  {name:25s}: {imp:.3f}")

    # Простой замер скорости инференса
    dummy_sample = X_test[0].reshape(1, -1)
    for _ in range(10):
        _ = xgb_model.predict_proba(dummy_sample)   # разогрев
    start = time.perf_counter()
    for _ in range(10000):
        _ = xgb_model.predict_proba(dummy_sample)
    elapsed = time.perf_counter() - start
    avg_ms = elapsed / 10000 * 1000
    print(f"\nAverage inference time per URL: {avg_ms:.4f} ms")

    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    model_path = BASE_DIR / 'ml' / 'model.pkl'    # сохраняем под именем model.pkl
    joblib.dump(xgb_model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == '__main__':
    main()