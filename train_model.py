import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from ml.features import extract_features

print("Загрузка данных...")
df = pd.read_csv('data/processed/url_dataset_features.csv')
print(f"Исходный датасет: {len(df)} записей")

feature_cols = [c for c in df.columns if c not in ['url', 'label']]

# БЕЗОПАСНЫЕ URL (label=0)
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
]

# ОПАСНЫЕ URL (label=1) - ДОБАВЛЯЕМ
dangerous_urls = [
    'http://185.130.5.253/login',
    'http://185.130.5.253/secure',
    'http://bit.ly/3xYz7Kq',
    'http://tinyurl.com/verify-account',
    'http://goo.gl/secure-login',
    'http://login.secure-update.ru/account/verify',
    'http://paypal.com.secure-login.xyz/login',
    'http://apple.com.verify-account.net/signin',
    'https://google.com.secure-login.ru',
    'http://secure-login.com',
    'http://account-verify.net',
    'http://confirm-identity.ru',
]

print(f"Добавляем {len(safe_urls)} доверенных URL...")
safe_features = [extract_features(url) for url in safe_urls]
safe_df = pd.DataFrame(safe_features, columns=feature_cols)
safe_df['label'] = 0
safe_df['url'] = safe_urls

print(f"Добавляем {len(dangerous_urls)} опасных URL...")
dangerous_features = [extract_features(url) for url in dangerous_urls]
dangerous_df = pd.DataFrame(dangerous_features, columns=feature_cols)
dangerous_df['label'] = 1
dangerous_df['url'] = dangerous_urls

# Объединяем
df = pd.concat([df, safe_df, dangerous_df], ignore_index=True)
print(f"После добавления: {len(df)} записей")

X = df[feature_cols]
y = df['label']

print(f"Признаков: {X.shape[1]}")
print(f"Распределение классов: 0={sum(y==0)}, 1={sum(y==1)}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Обучение модели...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

# Проверка
print("\nПроверка:")
test_urls = [
    'https://google.com',
    'https://vk.com',
    'http://185.130.5.253/login',
    'http://bit.ly/xxx',
    'http://login.secure-update.ru/account/verify',
]

for url in test_urls:
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_cols)
    proba = model.predict_proba(features_df)[0][1]
    if proba < 0.3:
        verdict = "Безопасно"
    elif proba > 0.7:
        verdict = "Опасно"
    else:
        verdict = "Подозрительно"
    print(f"  {url}: {verdict} ({proba*100:.1f}%)")

joblib.dump(model, 'ml/model.pkl')
print("\nМодель сохранена в ml/model.pkl")
