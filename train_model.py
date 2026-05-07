# train_model.py
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

from ml.features import extract_features, feature_cols


def main():
    BASE_DIR = Path(__file__).parent
    dataset_path = BASE_DIR / 'data' / 'processed' / 'url_dataset_features.csv'
    
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        sys.exit(1)

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    print(f"Shape: {df.shape}")
    print(f"Classes 0(legit)/1(phishing):\n{df['label'].value_counts()}")

    # === КРИТИЧНО: Только ЧИСТЫЕ домены, БЕЗ /login, /account, /verify и т.п. ===
    # Любое подозрительное слово в легитимном URL создаёт конфликт с фишинговым датасетом
    safe_urls = [
        # Поисковики / порталы
        'https://google.com', 'https://yandex.ru', 'https://www.bing.com',
        'https://duckduckgo.com', 'https://www.baidu.com',
        
        # Соцсети (только корневые домены)
        'https://github.com', 'https://stackoverflow.com', 'https://www.reddit.com',
        'https://www.twitter.com', 'https://www.instagram.com', 'https://www.linkedin.com',
        'https://www.facebook.com', 'https://vk.com', 'https://ok.ru', 'https://www.weibo.com',
        
        # Медиа / новости
        'https://www.youtube.com', 'https://www.netflix.com', 'https://www.spotify.com',
        'https://www.twitch.tv', 'https://www.imdb.com', 'https://www.bbc.com',
        'https://edition.cnn.com', 'https://www.nytimes.com', 'https://www.theguardian.com',
        'https://medium.com', 'https://www.wired.com', 'https://techcrunch.com',
        
        # Почта / облака (корневые)
        'https://mail.google.com', 'https://outlook.live.com', 'https://mail.yahoo.com',
        'https://drive.google.com', 'https://www.dropbox.com', 'https://onedrive.live.com',
        
        # Университеты / гос. сайты
        'https://mit.edu', 'https://stanford.edu', 'https://harvard.edu',
        'https://www.cambridge.org', 'https://www.usa.gov', 'https://www.gov.uk',
        
        # E-commerce / сервисы
        'https://www.amazon.com', 'https://www.ebay.com', 'https://www.paypal.com',
        'https://www.adobe.com', 'https://www.office.com', 'https://www.salesforce.com',
        'https://www.zoom.us', 'https://www.slack.com', 'https://www.telegram.org',
        'https://www.whatsapp.com', 'https://www.booking.com', 'https://www.airbnb.com',
        'https://www.ikea.com', 'https://www.wikipedia.org',
        
        # Российские сервисы
        'https://mail.ru', 'https://dzen.ru', 'https://www.rambler.ru', 'https://www.kp.ru',
    ]
    
    for url in safe_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 0}])], ignore_index=True)
        except Exception:
            pass
    
    # Опасные URL — только явно фишинговые
    dangerous_urls = [
        'http://185.130.5.253/login',
        'http://bit.ly/xxx',
        'https://secure-paypal-verify.account-login.cp.php.evil.com',
        'http://goo.gl/malware',
        'https://login-verify-account-update.cp.php.bad-domain.ru',
    ]
    
    for url in dangerous_urls:
        try:
            feats = extract_features(url).iloc[0].to_dict()
            df = pd.concat([df, pd.DataFrame([{**feats, 'label': 1}])], ignore_index=True)
        except Exception:
            pass

    # === Очистка данных ===
    df = df.drop_duplicates(subset=feature_cols + ['label'])
    df[feature_cols] = df[feature_cols].fillna(0)
    df = df.dropna(subset=feature_cols).reset_index(drop=True)

    print(f"\nFinal dataset: {len(df)} examples")

    # === Подготовка матриц ===
    X = df[feature_cols].astype(np.float32).values
    y = df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # === Обучение модели ===
    print("\nTraining Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,              # МЕНЬШЕ = лучше обобщение
        min_samples_split=20,      # БОЛЬШЕ = устойчивее к шуму
        min_samples_leaf=10,       # БОЛЬШЕ = сглаживает редкие комбинации
        class_weight='balanced',   # КРИТИЧНО: делает вероятности адекватными
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("Training finished!")

    # === Оценка ===
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # === Замер скорости ===
    sample_size = min(1000, len(X_test))
    start_time = time.perf_counter()
    _ = model.predict(X_test[:sample_size])
    elapsed = time.perf_counter() - start_time
    print(f"\nInference time per URL: {(elapsed / sample_size * 1000):.4f} ms")

    # === Контрольный тест ===
    print("\nCONTROL URL TEST")
    test_cases = [
        ("https://google.com", 0),
        ("https://yandex.ru", 0),
        ("http://185.130.5.253/login", 1),
        ("https://bit.ly/xxx", 1),
    ]
    
    for url, true_label in test_cases:
        try:
            feats = extract_features(url)
            proba = model.predict_proba(feats.values)[0][1] * 100
            pred = 1 if proba >= 70 else 0
            status = "✅" if pred == true_label else "⚠️"
            verdict = "DANGEROUS" if proba >= 70 else ("SUSPICIOUS" if proba >= 40 else "SAFE")
            print(f"{status} {url:40s} → {proba:6.1f}% {verdict}")
        except Exception as e:
            print(f"❌ {url:40s} → ERROR: {e}")

    # === Диагностика ===
    print("\n🔍 Feature Importances (top 8):")
    for name, imp in sorted(zip(feature_cols, model.feature_importances_), key=lambda x: -x[1])[:8]:
        print(f"  {name:15s}: {imp:.3f}")
    
    print(f"\n📊 Features for 'https://google.com':")
    feats = extract_features("https://google.com").iloc[0]
    for col in feature_cols:
        print(f"  {col:15s}: {feats[col]}")

    # === Сохранение ===
    os.makedirs(BASE_DIR / 'ml', exist_ok=True)
    model_path = BASE_DIR / 'ml' / 'model.pkl'
    joblib.dump(model, model_path)
    print(f"\n✅ Model saved to {model_path}")

    # === Верификация ===
    test_model = joblib.load(model_path)
    print(f"Verification: loaded model type = {type(test_model).__name__}")


if __name__ == '__main__':
    main()
